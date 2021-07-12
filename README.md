# check-techstack-vulnerabilities

```
if __name__ == "__main__":

    df_cvc, df_tech_stack = None, None
    tsv = TechStackVulnerabilities(
        techstackData={
            "spring_framework 5.2.9" : "cpe:/a:pivotal_software:spring_framework:5.2.9",
            "PostgreSQL 11.10" : "cpe:/a:postgresql:postgresql:11.10",
            "Amazon Corretto 1.8.0_252" : "cpe:/a:oracle:jdk:1.8.0:update_252",
            "Apache Tomcat 8.5.63" : "cpe:/a:apache:tomcat:8.5.63",
            "Apache Tomcat 9.0.43" : "cpe:/a:apache:tomcat:9.0.43"
        },

        output_report_path = "D:\\learnings\\Jile-techstack.xlsx"
    )
    tsv.makeXLfromDf()
```