#!/usr/bin/env python3
"""Load git metadata from extras/*.json files"""

import json
from pathlib import Path


def load_extras_metadata(extras_dir='extras'):
    """Load git metadata from extras JSON files

    Returns:
        dict: {image_key: {git_url, git_revision}}
    """
    extras_path = Path(extras_dir)

    if not extras_path.exists():
        return {}

    metadata = {}

    # Find all JSON files in extras directory
    json_files = list(extras_path.glob('*.json'))

    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            # extras/*.json is an array of component objects
            for component in data:
                image_key = component.get('image-key')
                git_url = component.get('git-url')
                git_revision = component.get('git-revision')

                if image_key:
                    metadata[image_key] = {
                        'git_url': git_url,
                        'git_revision': git_revision,
                        'commit_url': f"{git_url}/commit/{git_revision}" if git_url and git_revision else None
                    }
        except Exception:
            continue

    return metadata
