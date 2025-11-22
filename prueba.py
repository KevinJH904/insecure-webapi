# Código de ejemplo: suma de números impares
suma = sum(x for x in range(1, 101) if x % 2 != 0)
print(suma)

# ============================================================
# Ejemplo sencillo de conexión a SQLite y selección de datos
# ============================================================

import sqlite3

# 1. Conectar a la base de datos (se crea si no existe)
# Usando 'with' para asegurar que la conexión se cierre automáticamente
with sqlite3.connect('ejemplo.db') as conexion:
    # 2. Crear un cursor para ejecutar comandos SQL
    cursor = conexion.cursor()

    # 3. Crear una tabla de ejemplo (si no existe)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT NOT NULL,
            edad INTEGER
        )
    ''')

    # 4. Insertar datos de ejemplo (solo si la tabla está vacía)
    cursor.execute('SELECT COUNT(*) FROM usuarios')
    contador = cursor.fetchone()[0]
    
    if contador == 0:
        datos_ejemplo = [
            ('Juan Pérez', 'juan@example.com', 25),
            ('María García', 'maria@example.com', 30),
            ('Carlos López', 'carlos@example.com', 28),
            ('Ana Martínez', 'ana@example.com', 22)
        ]
        cursor.executemany(
            'INSERT INTO usuarios (nombre, email, edad) VALUES (?, ?, ?)',
            datos_ejemplo
        )
        conexion.commit()
        print("Datos de ejemplo insertados.")

    # 5. Seleccionar una columna de la tabla
    print("\n--- Selección de la columna 'nombre' ---")
    cursor.execute('SELECT nombre FROM usuarios')
    nombres = cursor.fetchall()

    for nombre in nombres:
        print(nombre[0])

    # 6. Seleccionar múltiples columnas
    print("\n--- Selección de nombre y email ---")
    cursor.execute('SELECT nombre, email FROM usuarios')
    resultados = cursor.fetchall()

    for nombre, email in resultados:
        print(f"Nombre: {nombre}, Email: {email}")

    # 7. Seleccionar con condición (WHERE)
    print("\n--- Usuarios mayores de 25 años ---")
    cursor.execute('SELECT nombre, edad FROM usuarios WHERE edad > 25')
    resultados = cursor.fetchall()

    for nombre, edad in resultados:
        print(f"{nombre} - {edad} años")

# 8. La conexión se cierra automáticamente al salir del bloque 'with'
print("\nConexión a la base de datos cerrada.")
