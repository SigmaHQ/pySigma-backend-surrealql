from .surrealql import surrealql_pipeline
# TODO: add all pipelines that should be exposed to the user of your backend in the import statement above.

pipelines = {
    "surrealql_pipeline": surrealql_pipeline,   # TODO: adapt identifier to something approproiate
}