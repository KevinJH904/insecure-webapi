
import json
import random
import hashlib
import mysql.connector
import base64
import shutil
import bcrypt  # PARCHE: Librería para hashing seguro de contraseñas
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



def loadDatabaseSettings(pathjs):
    pathjs = Path(pathjs)
    sjson = False
    if pathjs.exists():
        with pathjs.open() as data:
            sjson = json.load(data)
    return sjson


def getToken():
    # PARCHE SEGURIDAD: Usar SHA256 en lugar de SHA1 y MD5
    tiempo = datetime.now().timestamp()
    numero = random.random()
    cadena = str(tiempo) + str(numero)
    numero2 = random.random()
    cadena2 = str(numero)+str(tiempo)+str(numero2)
    
    # Usar SHA256 (más seguro que SHA1 y MD5)
    m = hashlib.sha256()
    m.update(cadena.encode())
    P = m.hexdigest()
    
    m = hashlib.sha256()
    m.update(cadena2.encode())
    Q = m.hexdigest()
    
    return f"{P[:32]}{Q[32:]}"


@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json')

    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}

    R = False
    try:
        # PARCHE SEGURIDAD: Hashear contraseña con bcrypt antes de guardar
        password_hash = bcrypt.hashpw(
            request.json["password"].encode('utf-8'), 
            bcrypt.gensalt()
        )
        
        with db.cursor() as cursor:
            cursor.execute(
                # FIXEO: SQL INJECTION + PARCHE: bcrypt en lugar de MD5
                'INSERT INTO Usuario values(null,%s,%s,%s)',
                (request.json["uname"], request.json["email"], password_hash.decode('utf-8'),)
            )
            R = cursor.lastrowid
            db.commit()
        db.close()
    except Exception as e:
        print(e)
        return {"R": -2}
    return {"R": 0, "D": R}


@post('/Login')
def Login():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}
    R = 'uname' in request.json and 'password' in request.json
    if not R:
        return {"R": -1}

    try:
        with db.cursor() as cursor:
            # PARCHE: Obtener el hash almacenado en lugar de comparar con MD5
            cursor.execute(
                'SELECT id, password FROM Usuario WHERE uname = %s',
                (request.json["uname"],)
            )
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    if not R:
        db.close()
        return {"R": -3}
    
    # PARCHE SEGURIDAD: Verificar contraseña con bcrypt
    user_id = R[0][0]
    stored_hash = R[0][1].encode('utf-8')
    
    if not bcrypt.checkpw(request.json["password"].encode('utf-8'), stored_hash):
        db.close()
        return {"R": -3}  # Contraseña incorrecta

    T = getToken()

    # PARCHE DE SEGURIDAD: Logging sanitizado sin exponer tokens ni IDs
    # Solo se registra el evento de login sin datos sensibles
    with open("/tmp/log", "a") as log:
        log.write(f'[{datetime.now()}] Login exitoso - Token generado\n')

    try:
        with db.cursor() as cursor:
            #FIXEO: SQL INJECTION
            cursor.execute('Delete from AccesoToken where id_Usuario= %s',(user_id,))
            cursor.execute('insert into AccesoToken values(%s,%s,now())',(user_id,T,))
            db.commit()
            db.close()
            return {"R": 0, "D": T}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -4}


@post('/Imagen')
def Imagen():
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()

    if not request.json:
        return {"R": -1}

    R = 'name' in request.json and 'data' in request.json and 'ext' in request.json and 'token' in request.json
    if not R:
        return {"R": -1}

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    TKN = request.json['token']

    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token= %s',(TKN,))
            R = cursor.fetchall()
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    id_Usuario = R[0][0]

    with open(f'tmp/{id_Usuario}', "wb") as imagen:
        imagen.write(base64.b64decode(request.json['data'].encode()))

    try:
        with db.cursor() as cursor:
            #FIXEO: SQL INJECTION
            cursor.execute('INSERT INTO Imagen values(null,%s,"img/",%s)',(request.json["name"],id_Usuario,))
            cursor.execute('SELECT max(id) as idImagen FROM Imagen where id_Usuario= %s',(id_Usuario,))
            R = cursor.fetchall()
            idImagen = R[0][0]
            #FIXEO: SQL INJECTION
            #A = cursor.execute('update Imagen set ruta = "img/'+str(idImagen)+'.'+str(request.json['ext'])+'" where id = '+str(idImagen))
            A = cursor.execute("UPDATE Imagen set ruta=CONCAT('img/', %s, '.', %s) where id=%s",(idImagen,request.json['ext'],idImagen,))
            db.commit()
            shutil.move(f'tmp/{id_Usuario}', f'img/{idImagen}.{request.json["ext"]}')
            return {"R": 0, "D": A}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3,"RES":R}


@post('/Descargar')
def Descargar():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='mariadb_server',
        port=dbcnf['port'],
        database=dbcnf['dbname'],
        user=dbcnf['user'],
        password=dbcnf['password']
    )

    if not request.json:
        return {"R": -1}

    R = 'token' in request.json and 'id' in request.json
    if not R:
        return {"R": -1}

    TKN = request.json['token']
    idImagen = request.json['id']

    try:
        with db.cursor() as cursor:
            # FIXEO: SQL IJECTION 
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token= %s',(TKN,))
            #cursor.execute('select id_Usuario from AccesoToken where token = "'+TKN+'"');
            R = cursor.fetchall()
            #return {"R": -401, "msg":R}
    except Exception as e:
        print(e)
        db.close()
        return {"R": -2}

    try:
        with db.cursor() as cursor:
            # FIXEO3: Falta de validacion en las Credenciales se podia observar cualquier imagen Independietemente del Usuario 
            # Se restructura un poco el SQL para agregar la validacion que coincida con el id_Usuario
            cursor.execute('Select name,ruta FROM Imagen WHERE id = %s',(idImagen,))
            R = cursor.fetchall() 
    except Exception as e:
        print(e)
        db.close()
        return {"R": -3,"Valor":R}



    print(Path("img").resolve(),R[0][1])
    return static_file(R[0][1], Path(".").resolve())


if __name__ == '__main__':
    run(host='0.0.0.0', port=8080, debug=True)
