from setuptools import setup, find_packages


def read_requirements():

    with open("requirements.txt") as f:

        requirements = [requirement.split("#")[0].strip() for requirement in f.read().split("\n") if requirement[0] != "#"]
        return requirements


setup(
    version="0.1",
    name="pyFireEye",
    description="",
    long_description="",
    url="https://git.cirt.emrsn.org/Libraries/pyFireEye",
    author="Isaiah Eichen",
    author_email="isaiah.eichen@emerson.com",
    packages=find_packages(),
    install_requires=read_requirements()
)