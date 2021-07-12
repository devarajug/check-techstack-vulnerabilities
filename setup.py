import pathlib
import setuptools

#The directory containing this file
BASE = pathlib.Path(__file__).parent

# The text of the readme file
README = (BASE / "README.md").read_text()

#This call to setup does all the work
setuptools.setup(
    name="check_techstack_vunerabilities",
    version="1.0.0",
    deecription="It generates xls file with known vulnerabilities of each techstack.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/devarajug/check-techstack-vulnerabilities",
    author="Devaraju Garigapati",
    author_email="devarajugarigapati@gmail.com",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(),
    include_package_data=True,
    install_requires=["pandas", "openpyxl", "lxml", "requests", "beautifulsoup4"],
    python_requires='>=3.6'
)
