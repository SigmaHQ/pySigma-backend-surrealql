import pytest
from sigma.collection import SigmaCollection
from sigma.backends.surrealql import SurrealQLBackend


@pytest.fixture
def surrealql_backend():
    return SurrealQLBackend()


def test_surrealql_and_expression(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' AND fieldB='valueB';"]
    )


def test_surrealql_or_expression(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldB='valueB';"]
    )


def test_surrealql_and_or_expression(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' OR fieldA='valueA2') AND (fieldB='valueB1' OR fieldB='valueB2');"
        ]
    )


def test_surrealql_or_and_expression(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE (fieldA='valueA1' AND fieldB='valueB1') OR (fieldA='valueA2' AND fieldB='valueB2');"
        ]
    )


def test_surrealql_in_expression(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == [
            "SELECT * FROM <TABLE_NAME> WHERE fieldA='valueA' OR fieldA='valueB' OR (fieldA IS NOT NONE AND string::starts_with(fieldA,'valueC'));"
        ]
    )


def test_surrealql_regex_query(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE fieldA=/foo.*bar/ AND fieldB='foo';"]
    )


def test_surrealql_cidr_query(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE (field IS NOT NONE AND string::starts_with(field,'192.168.'));"]
    )


def test_surrealql_field_name_with_whitespace(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE field_name='value';"]
    )


def test_surrealql_value_contains(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|contains: valueA
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE (fieldA IS NOT NONE AND string::contains(fieldA,'valueA'));"]
    )


def test_surrealql_value_startswith(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|startswith: valueA
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE (fieldA IS NOT NONE AND string::starts_with(fieldA,'valueA'));"]
    )


def test_surrealql_value_endswith(surrealql_backend: SurrealQLBackend):
    assert (
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|endswith: valueA
                condition: sel
        """
            )
        )
        == ["SELECT * FROM <TABLE_NAME> WHERE (fieldA IS NOT NONE AND string::ends_with(fieldA,'valueA'));"]
    )


def test_surrealql_fts_keywords_str(surrealql_backend: SurrealQLBackend):
    with pytest.raises(Exception) as e:
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - value1
                    - value2
                condition: keywords
        """
            )
        )
    assert (
        str(e.value)
        == "Value-only string expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )


def test_surrealql_fts_keywords_num(surrealql_backend: SurrealQLBackend):
    with pytest.raises(Exception) as e:
        surrealql_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                keywords:
                    - 1
                    - 2
                condition: keywords
        """
            )
        )
    assert (
        str(e.value)
        == "Value-only number expressions (i.e Full Text Search or 'keywords' search) are not supported by the backend."
    )
