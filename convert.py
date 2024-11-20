import re


def dot_to_dbml(dot_file_path, dbml_output_path):
    dbml_code = []
    relationships = []
    current_table = None

    with open(dot_file_path, "r") as dot_file:
        lines = dot_file.readlines()

        for line in lines:
            # Detect table start
            table_match = re.match(r"\s*(\w+)\s+\[label=<.*<B>(\w+)</B>.*>\];", line)
            if table_match:
                current_table = table_match.group(2)
                dbml_code.append(f"Table {current_table} {{")
                continue

            # Detect table columns (inside <TR><TD>)
            if current_table and "<TR><TD" in line:
                column_match = re.search(r"<FONT .*?>(.*?)</FONT>", line)
                if column_match:
                    column_data = column_match.group(1).split(":")
                    if len(column_data) == 2:
                        column_name = column_data[0].strip()
                        column_type = column_data[1].strip()
                        pk = " [pk]" if column_name.lower() == "id" else ""
                        dbml_code.append(f"    {column_name} {column_type}{pk}")

            # Detect end of table
            if current_table and "</TABLE>" in line:
                dbml_code.append("}\n")
                current_table = None

            # Detect relationships
            relationship_match = re.match(
                r'\s*(\w+)\s+->\s+(\w+)\s+\[label="(.*?)"\];', line
            )
            if relationship_match:
                source_table = relationship_match.group(1)
                target_table = relationship_match.group(2)
                relationship_label = relationship_match.group(3)
                source_column, target_column = relationship_label.split(" -> ")
                relationships.append(
                    f"Ref: {source_table}.{source_column} > {target_table}.{target_column}"
                )

    # Add relationships to DBML code
    if relationships:
        dbml_code.append("// Relationships")
        dbml_code.extend(relationships)

    # Write DBML to output file
    with open(dbml_output_path, "w") as dbml_file:
        dbml_file.write("\n".join(dbml_code))

    print(f"DBML code has been written to {dbml_output_path}")


# Example usage
dot_file_path = "authapp_models.dot"  # Path to your DOT file
dbml_output_path = "output.dbml"  # Path for the DBML output file
dot_to_dbml(dot_file_path, dbml_output_path)
