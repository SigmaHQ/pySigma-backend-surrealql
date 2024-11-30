![Tests](https://github.com/SigmaHQ/pySigma-backend-surrealql/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/de5623fbf07513f8c1170083f2d5b71c/raw/SigmaHQ-pySigma-backend-surrealql.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SurrealQL Backend

This is the SurrealQL backend for pySigma. It provides the package `sigma.backends.surrealql` with the `SurrealQLBackend` class.
This backend translates Sigma Rules into SurrealQL syntax to execute queries in SurrealDB. It was developed using the features provided by SurrealDB version 2.0.

It supports the following output formats:

* **default**: plain SurrealQL queries

This project is currently maintained by:

* [obviouslynotraffa](https://github.com/obviouslynotraffa/)


### Known issues/limitations
* This [issue](https://github.com/obviouslynotraffa/pySigma-backend-surrealql/issues/1)
* In the future, `AND` or `OR` lists could be converted into the `IN` operator, but this is not a priority for now
* In SurrealDB, it is necessary to create a specific index beforehand for full-text search functionality