const { Pool } = require('pg')
const pool = new Pool({
    user: 'zzz',
    host: 'localhost',
    database: 'task4',
    port: 5432
})
module.exports = pool