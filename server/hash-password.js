// hash-password.js
const bcrypt = require('bcrypt');

// 👇 ใส่รหัสผ่านที่คุณต้องการใช้สำหรับแอดมินตรงนี้
const plainPassword = '1234'; 

const saltRounds = 10;

bcrypt.hash(plainPassword, saltRounds, function(err, hash) {
    if (err) {
        console.error("Error hashing password:", err);
        return;
    }
    console.log("Your plain password is:", plainPassword);
    console.log("Your BCrypt hash is (copy this value):");
    console.log(hash);
});