# acm-operator-bundle - main branch

The main branch of this operator-bundle repository holds configuration and generated
manifests needed to build the ACM operator bundle image.

## Description of Branches

### The main Branch (this branch)

This is the branch that is checked out by the Gen Bundle Contents When Triggered workflow in this
repository in order to get the front-end script (and its configuration) that then obtains and runs
the bundle-generation "business logic"c from the `stolostron/release` repo's `master` branch.

This branch does not contain any generated artifacts and thus will probably never be the source
branch for an image build.

The copies of workflows, scripts or configuration file sin this branch should be relatively static,
and in particular not need any release-to-release updates to change version numbers and the like.

The usual/required files in this branch:

- `.github/workflows/gen-bundle-contents-when-triggered.yaml` - The main-branch copy of the bundle
content generation workflow.  [1]

- `tools/run-script-from-tools-repo` - The "front" end script which is invoked from the
Gen Bundle Contents When Triggered workflow.  This script clones the `release` repo at a
specified branch and then runs a target "business-logic" from the cloned copy, as defined
in configuration.

- `config/config-vars` - The configuration file (source'd Bash fragment) that provides
configuration into to the front-end script.

Notes:

- Note [1]: Because of the way GitHub Actions works, this same workflow-definition Yaml file
will also be in the `release-bracnh-template` branch and each release branch, and should
be identical across all instances. In fact, hopefully it should be identical or close to
it across all bundle-building repos.  A "reference" copy of this workflow definition can be
found in the `stolostron/release` repo.

### The release-branch-template Branch

A branch whose contents serve as a template for the creation of a new release branch. 

This branch does not contain any generated artifacts and thus will probably never be the
source branch for an image build.

See "Setting Up A New Release Branch" below.

### backplane-x.y Branches (Release Branches)

A series of release branches, that is branches that contain the generated operator bundle contents
for a given release.  These branches are the ones to which bundle-building-request PRs should be
targeted and from which operator bundle images are built.


## Setting Up a New Release Branch

The `release-branch-template` branch is intended to be a template branch from which new release
branches are cut.  The following is a suggested procedure for setting up  a new release branch.

##### Step 1: Ensure Template Branch is Up-To-Date for  the Current In-Dev Release

- Ensure that the `release-branch-template` branch contains the latest copies of configuration
for the in-dev releases, just in case updates were made directly in the in-dev release branch
without being made in the template branch as well.

- Configuration info to pay special attention to (because it often changes during the dev cycle) is
the configuration of OCP versions and the `{acm,mce}-manifest-gen-config.json` files that are
updated when components are added or removed.

##### Step 2: Update Template Branch for the New Release

- Update configuration files to reflect the usual *x.y* to *x.y+1* changes.  Below is a  list of
typical changes needed:

  - `README.md`:
    - Update the text to mention the correct feature release number in "x.y" form.

  - `Z_RELEASE_VERSION`:
    - Fill in the release number in x.y.z form.

  - `config/{acm,mce}-bundle-gen.config`:
    - Update the ocp_versions variable to be the range of OCP release for which this  new release
      is to be published in the redhat-operators catalog.  (This is mainly for backward compatibility
      with CPaaS builds.)

    - Ensure `add_iteration_suffix=1` is set so that pre-release builds get *-nnn* suffixes add to
      the CSV/bundle versions.

  - `config/{acm,mce>-manifest-gen-config.json`:
    - Update the `konflux-component-and-image-suffix` property to be the suffix that will be
      used on the Konflux Component resources for this new release.

  - `config/Dockerfile.in`:
    - Update labels to be used on bundle images if we are changing our labeling conventions.
       Note: No need to update any verion-number-released labels here as those are automatically
      injected/substituted in place of the `BUNDLE_VERSION` placeholder string.

- Commit the updates with a commit message like "Update configuration for new release x.y"

##### Step 3: Cut the New Release Branch

Create the new release branch as an orphaned branch off of the `release-branch-template` branch:

```
git checkout release-branch-template
git checkout --orphan <new-release-branch>
# The starting content of the new branch will already be staged and ready to commit
git commit --signoff -m "Create branch for release x.y"
git push
```

We suggest that each release branch starts as an orphan (also sometimes called unrelated) branch to
keep them history distinct and not intertwisted with the history of any other release branch.
