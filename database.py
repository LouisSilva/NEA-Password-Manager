import sqlite3
from sqlite3 import Error
from os.path import isfile


class PasswordDatabase:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.curs = self.conn.cursor()
        self.curs.execute("""CREATE TABLE IF NOT EXISTS passwords (
                                                             ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                                                             Username TEXT,
                                                             Email TEXT,
                                                             Password TEXT NOT NULL,
                                                             App TEXT NOT NULL
                                                         );""")

    def selectAll(self):
        return self.curs.execute('''SELECT * FROM passwords''')

    def addRecord(self, record):
        try:
            record = (username, email, password, app)
            self.curs.exectute(f"""INSERT INTO passwords
                                           VALUES (NULL, ?, ?, ?, ?)""", record)
            self.conn.commit()
            self.load_Database()
        except Exception as e:
            print(error)

# class PasswordDatabase:
#     def __init__(self):
#         setup = True
#         if isfile("passwords.db"): setup = False
#
#         self.connection = None
#
#         self.connection = sqlite3.connect(":memory:")
#         self.cursor = self.connection.cursor()
#         if setup: self.__create_tables()
#
#     def __del__(self):
#         self.connection.close()
#
#     def __create_tables(self):
#         self.cursor.execute("""CREATE TABLE IF NOT EXISTS passwords (
#                                      ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
#                                      Username TEXT,
#                                      Email TEXT,
#                                      Password TEXT NOT NULL,
#                                      App TEXT NOT NULL
#                                  );""")
#
#     def get_database(self):
#         try:
#             self.cursor.execute("""SELECT * FROM passwords""")
#             rows = self.cursor.fetchall()
#             return rows
#
#         except Exception as e:
#             print(e)
#
#     def insert_multiple_into_table(self, values):
#         try:
#             for i in range(len(values)):
#                 self.cursor.execute(f"""INSERT INTO passwords
#                                        VALUES (NULL, ?, ?, ?, ?)""", values[i])
#                 self.connection.commit()
#
#         except Exception as e:
#             print(e)
#
#     def insert_single_into_table(self, value):
#         try:
#             self.cursor.execute(f"""INSERT INTO passwords
#                                    VALUES (NULL, ?, ?, ?, ?)""", value)
#             self.connection.commit()
#
#         except Exception as e:
#             print(e)
#
#     def update_table(self, values):
#         try:
#             for i in range(len(values)):
#                 self.cursor.execute("""UPDATE passwords
#                                         SET Username = ?,
#                                             Email = ?,
#                                             Password = ?,
#                                             App = ?
#                                         WHERE ID = ?""", (values[i][0], values[i][1], values[i][2], values[i][3], values[i][4]))
#                 self.connection.commit()
#
#         except Exception as e:
#             print(e)


# def create_table(conn, create_table_sql):
#     """ create a table from the create_table_sql statement"""
#     try:
#         c = conn.cursor()
#         c.execute(create_table_sql)
#     except Error as e:
#         print(e)
#
#
# def main():
#     database = r"passwords.db"
#
#     sql_create_master_password_table = """ CREATE TABLE IF NOT EXISTS master_password (
#                                         id integer PRIMARY KEY,
#                                         Master_password text NOT NULL,
#                                     ); """
#
#     sql_create_passwords_table = """CREATE TABLE IF NOT EXISTS passwords (
#                                     id integer PRIMARY KEY,
#                                     Username text,
#                                     Email text,
#                                     Password text NOT NULL
#                                     App text NOT NULL,
#                                 );"""
#
#     # create a database connection
#     conn = create_connection(database)
#
#     # create tables
#     if conn is not None:
#         # create projects table
#         create_table(conn, sql_create_master_password_table)
#
#         create_table(conn, sql_create_passwords_table)
#     else:
#         # create tasks table
#         print("Error! cannot create the database connection.")


if __name__ == "__main__":
    password_db = PasswordDatabase()
