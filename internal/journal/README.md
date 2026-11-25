# Create journal schema

Schema 2 adds the optional `op_id` field for a canonical, validated operation
correlation ID. It is informational and is never ownership or authorization
proof. Records without it remain valid. The reader accepts schema 1 records
written before this field existed and schema 2 records with or without it;
unknown fields and unsupported schema versions are rejected.
