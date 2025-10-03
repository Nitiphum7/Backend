const { response } = require("express"); 
const {Pool} = require("pg"); 
const pool = new Pool({
    user: 'postgres',      
    host: 'localhost',         
    database: 'graduate_tracking',   
    password: '1234',  
    port: 5432,                 
  });

  pool.connect()
  .then(() => console.log('Connected to PostgreSQL'))
  .catch(err => console.error('PostgreSQL connection error:', err.message));

module.exports = pool;
