import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sshcrosscloud-ANBO", # Replace with your own username
    version="0.0.1",
    author="Antoine Bourayne",
    author_email="bourayneantoine@gmail.com",
    description="A tool to easily use cloud virtual machines",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/antoinebourayne/sshcrosscloud",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Linux",
    ],
    python_requires='>=3.6',
)