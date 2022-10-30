# Stackzilla Provider Template Repository

## INSTRUCTIONS ON USING THIS TEMPLATE
1) After creating a new repository with this template, find and replace ALL instances of "<provider_name>" with the name of your provider. At that point, all invoke tasks, and GitHub workflows should be operational.
2) Rename the ./stackzilla/provider/< provider_name >/ directory to match the name of your provider
3) Rename the `resource.py` file in the directory that you renamed in step 2 to match whatever your resource is. Example: if I'm creating a provider for AWS EC2 instances, I'd likely call that file `instance.py`.

<p align="center">
    <img src="https://github.com/Stackzilla/stackzilla/blob/main/docs/assets/images/zilla_and_blocks.png?raw=true"  alt="stackzilla" width="500"/>
</p>

[![Python 3.7 | 3.8 | 3.9 | 3.10](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10-blue)](https://pypi.org/project/stackzilla/)
[![pyPI](https://img.shields.io/pypi/v/<provider_name>)](https://pypi.org/project/<provider_name>/)


TOOD: Insert provider project description here.

# Installation
Install and update using [pip](https://pip.pypa.io/en/stable/getting-started/).

```bash
pip install -U <provider_name>
```

View the <provider_name> PyPI package [here](https://pypi.org/project/<provider_name>/).


## A simple blueprint
TODO

# Contributing
To get started with contributing to the <provider_name> project, visit the developer documentation. Thank you for your interest!

# License
<provider_name> is licensed under the GNU Affero General Public License v3.0 license See [LICENSE](https://github.com/Stackzilla/stackzilla/blob/main/LICENSE) for more information.
