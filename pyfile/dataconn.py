
from sqlite3 import Error
from pysqlcipher3 import dbapi2 as sqlite


def create_connection(path):
    connection = None
    try:
        connection=sqlite.connect(path)
    
    except Error as e:
        print(f"The error '{e}' occurred")

    return connection