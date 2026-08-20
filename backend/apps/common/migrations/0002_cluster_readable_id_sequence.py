from django.db import migrations


SEQUENCE_NAME = "readable_id_cluster_seq"
PREFIX = "cluster"
TABLE_NAME = "agentic_incident_clusters"
FIELD_NAME = "cluster_id"


def create_and_sync_sequence(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(f"CREATE SEQUENCE IF NOT EXISTS {SEQUENCE_NAME}")
        cursor.execute(
            f"""
            SELECT COALESCE(MAX(substring({FIELD_NAME} FROM %s)::bigint), 0)
            FROM {TABLE_NAME}
            WHERE {FIELD_NAME} ~ %s
            """,
            [f"^{PREFIX}_([0-9]+)$", f"^{PREFIX}_[0-9]+$"],
        )
        max_number = cursor.fetchone()[0]
        if max_number:
            cursor.execute("SELECT setval(%s::regclass, %s, true)", [SEQUENCE_NAME, max_number])
        else:
            cursor.execute("SELECT setval(%s::regclass, 1, false)", [SEQUENCE_NAME])


def drop_sequence(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(f"DROP SEQUENCE IF EXISTS {SEQUENCE_NAME}")


class Migration(migrations.Migration):

    dependencies = [
        ("common", "0001_readable_id_sequences"),
        ("agentic", "0006_hunthypothesis_huntfinding_huntplan_and_more"),
    ]

    operations = [
        migrations.RunPython(create_and_sync_sequence, reverse_code=drop_sequence),
    ]
