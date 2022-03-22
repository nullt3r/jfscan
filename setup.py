import pathlib
from setuptools import setup, find_packages



# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="jfscan",
    version="1.1.4",
    description="A Masscan wrapper with some useful modules. I am not responsible for any damages. You are responsible for your own actions. Attacking targets without prior mutual consent is illegal.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/nullt3r/jfscan",
    author="nullt3r",
    author_email="nullt3r@bugdelivery.com",
    license="MIT",
    python_requires='>=3.6, <4',
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.9",
    ],
    packages=find_packages(),
    install_requires=["validators", "requests", "tldextract", "dnspython"],
    entry_points={
        "console_scripts": [
            "jfscan=jfscan.__main__:main",
        ]
    },
)
