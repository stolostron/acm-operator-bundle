#!/usr/bin/env python3
"""Load git metadata from extras/*.json files and component registry"""

import json
import yaml
from pathlib import Path


def load_component_registry(registry_file='component-registry-acm.yaml'):
    """Load component registry mapping

    Returns:
        dict: {image_key: {squad, jira_component, repository, ...}}
    """
    registry_path = Path(registry_file)
    if not registry_path.exists():
        return {}

    try:
        with open(registry_path, 'r') as f:
            data = yaml.safe_load(f)

        registry = {}
        for comp in data.get('components', []):
            comp_data = {
                'squad': comp.get('squad'),
                'jira_component': comp.get('jira_component'),
                'repository': comp.get('repository'),
                'prodseccomponent': comp.get('prodseccomponent')
            }

            # Use konflux_component as primary key
            key = comp.get('konflux_component') or comp.get('name')
            if key:
                registry[key] = comp_data

                # Also create alternate keys for matching scan component names
                # Scan uses underscores: acm_must_gather
                # Registry uses hyphens + suffix: must-gather-acm
                # Create key without suffix and with underscores
                key_no_suffix = key.replace('-acm', '').replace('-mce', '')
                key_underscore = key_no_suffix.replace('-', '_')
                registry[key_underscore] = comp_data

        return registry
    except Exception:
        return {}


def load_extras_metadata(extras_dir='extras'):
    """Load git metadata from extras JSON files

    Returns:
        dict: {image_key: {git_url, git_revision}}
    """
    extras_path = Path(extras_dir)

    if not extras_path.exists():
        return {}

    metadata = {}

    # Load component registry
    registry = load_component_registry()

    # Collect all unique squads from registry
    all_squads = set()
    for comp_data in registry.values():
        squad = comp_data.get('squad')
        if squad:
            all_squads.add(squad)

    # Find all JSON files in extras directory
    json_files = list(extras_path.glob('*.json'))

    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            # extras/*.json is an array of component objects
            for component in data:
                image_key = component.get('image-key')
                image_name = component.get('image-name')
                git_url = component.get('git-url')
                git_revision = component.get('git-revision')

                if image_key:
                    # Merge extras data with registry data
                    comp_data = {
                        'image_name': image_name,
                        'git_url': git_url,
                        'git_revision': git_revision,
                        'commit_url': f"{git_url}/commit/{git_revision}" if git_url and git_revision else None
                    }

                    # Add registry data if available
                    if image_key in registry:
                        comp_data.update(registry[image_key])

                    metadata[image_key] = comp_data
        except Exception:
            continue

    # Add all registry components even if not in extras (for squad/jira data)
    for image_key, reg_data in registry.items():
        if image_key not in metadata:
            metadata[image_key] = reg_data.copy()

    # Add all squads as special key
    metadata['all_squads'] = all_squads

    return metadata
