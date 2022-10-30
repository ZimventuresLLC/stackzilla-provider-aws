"""Tasks that can be executed via 'invoke <cmd>' for developers."""
from invoke import task

SOURCE_ROOT = '<provider_name>'

@task
def clean(c):
    """Clean out any build files or Python caches."""
    c.run('py3clean .')

@task
def lint(c):
    """Perform linting duties on the codebase."""
    c.run(f'isort {SOURCE_ROOT}')
    c.run(f'pydocstyle {SOURCE_ROOT}')
    c.run(f'pylint ./{SOURCE_ROOT}')

@task
def test(c):
    """Run all of the tests!"""
    c.run(f'pytest {SOURCE_ROOT}')

@task
def build(c):
    """Build a wheel"""
    c.run('python -m pip install build twine')
    c.run('python setup.py bdist_wheel --universal')

@task
def publish_test(c):
    """Publish the distribution to the test PyPI server"""
    c.run('twine upload -r testpypi dist/* ')

@task
def publish(c):
    """Publish the distribution to the production PyPI server"""
    c.run('twine upload dist/*')

@task
def serve_docs(c):
    """Start running the Jekyll server to serve documentation."""
    c.run('cd ./docs; bundle exec jekyll serve')
