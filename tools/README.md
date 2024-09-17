Notes:

The `run-script-from-tools-repo` script found in this directory is a front-end
script that clones the release-tools repository and then invokes a target script
from the cloned repository.  The repository and branch to clone and the pathame
of the target script are set by configuration variables defined in a (sourced)
Bash snippet that lives in the ocnfig directory of this branch.

The front-end script is intended to be generic and version/release-depednency free so that
the same code can be copied into the main branch of each bundle repository we will maintain
for ACM and MCE, and hopefully there will be infrequent need to update those copies.
If updates are needed, the master copy in the release-tools repo should be the spot
that is first updated, and then manually propagated into each of the bundle repos.
(There is no automatic sync mechanism in place.)

