# Check Techstack Vulnerabilities
The use of this module is to generate xls file containing known vulnerabilities of tech details given as input.

# Installation

```
pip install check-techstack-vulnerabilities
```

# How to use
```
from chce_techstack_vulnerabilities.TechStack import TechStackVulnerabilities

# project techstack details sysntax must be like below

project_tech_stack_details = {
    "tech_name version" : "cpe url",
}

# Example 
project_tech_stack_details = {
    "spring_framework 5.2.9" : "cpe:/a:pivotal_software:spring_framework:5.2.9",
    "PostgreSQL 11.10" : "cpe:/a:postgresql:postgresql:11.10",
    "Amazon Corretto 1.8.0_252" : "cpe:/a:oracle:jdk:1.8.0:update_252",
    "Apache Tomcat 8.5.63" : "cpe:/a:apache:tomcat:8.5.63",
}

# cpe url can be found in [NVD](https://nvd.nist.gov/products/cpe/search) website 

# License

Copyright (c) 2021 Devaraju Garigapati

This repository is licensed under the MIT license.
See LICENSE for details.