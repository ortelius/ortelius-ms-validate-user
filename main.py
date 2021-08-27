import os
from http import HTTPStatus

import jwt
import psycopg2
import pybreaker
import sqlalchemy.pool as pool
from flask import Flask, request, send_from_directory
from flask_restful import Api, Resource
from flask_swagger_ui import get_swaggerui_blueprint
from webargs import fields, validate
from webargs.flaskparser import abort, parser


#pylint: disable=unused-argument
@parser.error_handler
def handle_request_parsing_error(err, req, schema, *, error_status_code, error_headers):
    abort(HTTPStatus.BAD_REQUEST, errors=err.messages)

# Init Flask
app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)


# swagger config
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.yml'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "ortelius-ms-validate-user"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

# Init db connection
db_host = os.getenv("DB_HOST", "localhost")
db_name = os.getenv("DB_NAME", "postgres")
db_user = os.getenv("DB_USER", "postgres")
db_pass = os.getenv("DB_PASS", "postgres")
db_port = os.getenv("DB_PORT", "5432")
id_rsa_pub = os.getenv("RSA_FILE", "ortelius_rsa.pub")
public_key = open(id_rsa_pub, 'r').read()

# connection pool config
conn_pool_size = int(os.getenv("POOL_SIZE", "3"))
conn_pool_max_overflow = int(os.getenv("POOL_MAX_OVERFLOW", "2"))
conn_pool_timeout = float(os.getenv("POOL_TIMEOUT", "30.0"))

conn_circuit_breaker = pybreaker.CircuitBreaker(
    fail_max=1,
    reset_timeout=10,
)


@conn_circuit_breaker
def create_conn():
    conn = psycopg2.connect(host=db_host, database=db_name, user=db_user, password=db_pass, port=db_port)
    return conn

# connection pool init
mypool = pool.QueuePool(create_conn, max_overflow=conn_pool_max_overflow, pool_size=conn_pool_size, timeout=conn_pool_timeout)

# health check endpoint


class HealthCheck(Resource):
    def get(self):
        try:
            conn = mypool.connect()
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            conn.close()
            if cursor.rowcount > 0:
                return ({"status": 'UP', "service_name": 'ortelius-ms-validate-user'}), HTTPStatus.OK
            return ({"status": 'DOWN'}), HTTPStatus.SERVICE_UNAVAILABLE

        except Exception as err:
            print(err)
            return ({"status": 'DOWN'}), HTTPStatus.SERVICE_UNAVAILABLE


api.add_resource(HealthCheck, '/health')


class ValidateUser(Resource):

    def get(self):
        result = []                                # init result to be empty
        userid = -1                                # init userid to -1
        uuid = ''                                  # init uuid to blank
        conn = mypool.connect()                    # create db connection

        token = request.cookies.get('token', None)  # get the login token from the cookies
        if (token is None):                        # no token the fail
            return "Authorization Failed", HTTPStatus.UNAUTHORIZED
        try:
            decoded = jwt.decode(token, public_key, algorithms=["RS256"])  # decypt token
            userid = decoded.get('sub', None)           # get userid from token
            uuid = decoded.get('jti', None)             # get uuid from token
            if (userid is None):                        # no userid fail
                return 'Invalid userid', HTTPStatus.UNAUTHORIZED
            if (uuid is None):                          # no uuid fail
                return 'Invalid login token', HTTPStatus.UNAUTHORIZED
        except jwt.InvalidTokenError as err:
            return getattr(err, 'message', str(err)), HTTPStatus.UNAUTHORIZED   # jwt error return jwt msg

        try:
            authorized = False      # init to not authorized

            csql = "DELETE from dm.dm_user_auth where lastseen < current_timestamp - interval '1 hours'"  # remove stale logins
            sql = "select count(*) from dm.dm_user_auth where id = (%s) and jti = (%s)"  # see if the user id authorized

            cursor = conn.cursor()  # init cursor
            cursor.execute(csql)   # exec delete query
            cursor.close()         # close the cursor so don't have a connection leak
            conn.commit()          # commit the delete and free up lock

            params = (userid, uuid, )   # setup parameters to count(*) query
            cursor = conn.cursor()      # init cursor
            cursor.execute(sql, params)  # run the query

            row = cursor.fetchone()     # fetch a row
            rowcnt = 0                  # init counter
            while row:                  # loop until there are no more rows
                rowcnt = row[0]         # get the 1st column data
                row = cursor.fetchone()  # get the next row
            cursor.close()              # close the cursor so don't have a connection leak

            if (rowcnt > 0):            # > 0 means that user is authorized
                authorized = True       # set authorization to True
                usql = "update dm.dm_user_auth set lastseen = current_timestamp where id = (%s) and jti = (%s)"  # sql to update the last seen timestamp
                params = (userid, uuid, )       # setup parameters to update query
                cursor = conn.cursor()          # init cursor
                cursor.execute(usql, params)    # run the query
                cursor.close()                  # close the cursor so don't have a connection leak
                conn.commit()                   # commit the update and free up lock

            if (not authorized):       # fail API call if not authorized
                conn.close()
                return "Authorization Failed", HTTPStatus.UNAUTHORIZED

            query_args_validations = {
                "domains": fields.Str(validate=validate.OneOf(["y", "Y", "n", "N"]))
            }

            parser.parse(query_args_validations, request, location="query")

            get_domains = request.args.get('domains', None)     # get the domains value from the query string

            if (get_domains is not None and get_domains.lower() == 'y'):    # get the list of domains for the user if domains=Y
                domainid = -1
                sql = "SELECT domainid FROM dm.dm_user WHERE id = (%s)"
                cursor = conn.cursor()  # init cursor
                params = (userid, )
                cursor.execute(sql, params)
                row = cursor.fetchone()
                while row:
                    domainid = row[0]
                    row = cursor.fetchone()
                cursor.close()

                sql = """WITH RECURSIVE parents AS
                        (SELECT
                                id              AS id,
                                ARRAY [id]      AS ancestry,
                                NULL :: INTEGER AS parent,
                                id              AS start_of_ancestry
                            FROM dm.dm_domain
                            WHERE
                                domainid IS NULL and status = 'N'
                            UNION
                            SELECT
                                child.id                                    AS id,
                                array_append(p.ancestry, child.id)          AS ancestry,
                                child.domainid                              AS parent,
                                coalesce(p.start_of_ancestry, child.domainid) AS start_of_ancestry
                            FROM dm.dm_domain child
                                INNER JOIN parents p ON p.id = child.domainid AND child.status = 'N'
                            )
                            SELECT ARRAY_AGG(c)
                            FROM
                            (SELECT DISTINCT UNNEST(ancestry)
                                FROM parents
                                WHERE id = (%s) OR (%s) = ANY(parents.ancestry)) AS CT(c)"""

                cursor = conn.cursor()  # init cursor
                params = (domainid, domainid, )
                cursor.execute(sql, params)
                row = cursor.fetchone()
                while row:
                    result = row[0]
                    row = cursor.fetchone()
            conn.close()
            return result

        except Exception as err:
            print(err)
            conn.rollback()
            return ({"message": str(err)}), HTTPStatus.INTERNAL_SERVER_ERROR


##
# Actually setup the Api resource routing here
##
api.add_resource(ValidateUser, '/msapi/validateuser')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
