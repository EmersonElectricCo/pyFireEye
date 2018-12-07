from setuptools import setup, find_packages


def read_requirements():

    with open("requirements.txt") as f:

        requirements = [requirement.split("#")[0].strip() for requirement in f.read().split("\n") if requirement[0] != "#"]
        return requirements


setup(
    version="1.0",
    name="pyFireEye",
    description="Python API bindings for FireEye Products",
    long_description="",
    url="https://gitlab.com/EmersonElectricCo/pyFireEye",
    author="Isaiah Eichen, Grant Steiner, Timothy Lemm",
    author_email="isaiah.eichen[at]emerson.com, grant.steiner[at]emerson.com, timothy.lemm[at]emerson.com",
    packages=find_packages(),
    install_requires=read_requirements()
)
