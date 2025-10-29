const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const pool = require('./db'); 
const jwt = require('jsonwebtoken');
const iconv = require('iconv-lite');
require('dotenv').config();

// 2. ตั้งค่า Express App
const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = 3000;

if (!JWT_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET is not defined! Please check your .env file.");
    process.exit(1); // หยุดการทำงานของ server
}
// 3. ใช้งาน Middleware
const corsOptions = {
  origin: '*', 
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
  optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 4. ตั้งค่า Multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const decodedOriginalName = iconv.decode(Buffer.from(file.originalname, 'binary'), 'utf8');
    const decodedFieldName = iconv.decode(Buffer.from(file.fieldname, 'binary'), 'utf8');

    const userId = req.user?.userId || 'user'; 
    const uniqueSuffix = Date.now();
    const extension = path.extname(decodedOriginalName);

    // สร้างชื่อไฟล์ที่ปลอดภัยและอ่านง่ายขึ้น
    const safeFieldName = decodedFieldName.replace(/[^a-zA-Z0-9ก-๙]/g, '_').substring(0, 30);
    
    cb(null, `${userId}-${safeFieldName}-${uniqueSuffix}${extension}`);
  }
});

const upload = multer({ storage: storage });


const getStudentDetails = async (req, res, next) => {
    const studentId = req.params.studentId || req.params.userId;
    try {
        let userId;

        const userLookupRes = await pool.query(
            'SELECT user_id FROM student_profiles WHERE student_id = $1',
            [studentId]
        );

        if (userLookupRes.rows.length === 0) {
            console.log(`[DEBUG] Student with student_id ${studentId} not found in student_profiles.`);
            return res.status(404).json({ message: 'ไม่พบนักศึกษาที่มีรหัสนี้' });
        } else {
            userId = userLookupRes.rows[0].user_id;
            console.log(`[DEBUG] Found user_id: ${userId} for student_id: ${studentId}`);
        }

        // --- แก้ไขตรงนี้: ดึงแค่ profile และ submissions พอ ---
        const profilePromise = pool.query(`
            SELECT
                u.id, u.email,
                u.prefix_th, u.first_name_th, u.last_name_th,
                u.prefix_en, u.first_name_en, u.last_name_en, --  <-- เพิ่ม 3 คอลัมน์นี้
                sp.*,
                p.name as program_name, d.name as department_name, ss.status_name
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            LEFT JOIN student_statuses ss ON sp.status_id = ss.id
            WHERE u.id = $1;
        `, [userId]);

        const submissionsPromise = pool.query(`
            SELECT 
                ds.id, ds.submission_date, dt.type_name, dst.status_name
            FROM document_submissions ds
            JOIN document_types dt ON ds.document_type_id = dt.id
            JOIN document_statuses dst ON ds.status_id = dst.id
            WHERE ds.student_user_id = $1
            ORDER BY ds.submission_date DESC;
        `, [userId]);
        
        // --- เอา advisorsPromise ออกไป ---
        const [profileRes, submissionsRes] = await Promise.all([
            profilePromise, 
            submissionsPromise
        ]);
        
        console.log(`[DEBUG] Successfully fetched profile and submissions for user_id: ${userId}.`);

        // --- เอา advisors ออกจาก JSON ที่ส่งกลับไป ---
        res.json({
            profile: profileRes.rows[0],
            submissions: submissionsRes.rows,
        });

    } catch (error) {
        console.error(`[ERROR] Error fetching details for student ID: ${studentId}`, error);
        next(error);
    }
};
const toNull = (value) => (value === '' ? null : value);

// =================================================================
//  API Endpoints
// =================================================================

// --- API สำหรับตรวจสอบ Token และดึงข้อมูลผู้ใช้ปัจจุบัน ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        // ถ้าไม่มี token เลย ให้ส่ง 401 Unauthorized
        return res.sendStatus(401);
    }

    jwt.verify(token, JWT_SECRET, (err, user) => { 
        if (err) {
            // Token ไม่ถูกต้อง/หมดอายุ
            return res.sendStatus(403); 
        }
        req.user = user;
        next();
    });
};

app.get('/api/auth/verify', authenticateToken, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (token == null) {
            return res.sendStatus(401); // 401 Unauthorized
        }

        // 1. เปลี่ยนมาใช้ try...catch กับ jwt.verify โดยตรง
        // ถ้า token ผิด, มันจะโยน error ไปที่ catch block เอง
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId;
        
        // 2. ย้าย Query ออกมาทำงานตามลำดับปกติ
        const userQuery = `
            SELECT 
                u.id, u.email, u.has_signed, u.signature_image_url,
                u.prefix_th, u.first_name_th, u.last_name_th,
                r.role_name,
                sp.student_id,
                sp.degree, 
                p.name as program_name,
                d.name as department_name 
            FROM users u
            JOIN roles r ON u.role_id = r.id
            LEFT JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE u.id = $1;
        `;
        const userRes = await pool.query(userQuery, [userId]);
        
        if (userRes.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(userRes.rows[0]);

    } catch (error) {
        // 3. catch block นี้จะดักจับได้ทั้ง token ผิด และ db error
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.sendStatus(403); // 403 Forbidden
        }
        // ถ้าเป็น error อื่นๆ ให้ส่ง 500
        console.error("Verify API Error:", error);
        res.status(500).json({ message: 'Server error' });
    }
});

// --- API สำหรับการ Login ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'กรุณากรอกอีเมลและรหัสผ่าน' });
    }

    try {
        // 1. ค้นหาผู้ใช้และ Role จากตาราง users
        const userResult = await pool.query(
            'SELECT u.id, u.email, u.password_hash, u.has_signed, r.role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.email = $1',
            [email]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: 'ไม่พบบัญชีผู้ใช้นี้' });
        }

        const user = userResult.rows[0];

        // 2. ตรวจสอบรหัสผ่าน
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
        }

        // 3. ดึงข้อมูลโปรไฟล์เพิ่มเติมตาม Role
        let profileData = {};
        if (user.role_name === 'student') {
            const profileResult = await pool.query(
                `SELECT u.prefix_th, u.first_name_th, u.last_name_th, sp.student_id, p.name as program_name
                 FROM users u
                 JOIN student_profiles sp ON u.id = sp.user_id
                 LEFT JOIN programs p ON sp.program_id = p.id
                 WHERE u.id = $1`, [user.id]
            );
            if (profileResult.rows.length > 0) {
                profileData = profileResult.rows[0];
            }
        } else if (user.role_name === 'advisor' || user.role_name === 'program_chair') {
            const profileResult = await pool.query(
                `SELECT u.prefix_th, u.first_name_th, u.last_name_th, ap.advisor_id, ap.academic_position
                 FROM users u
                 JOIN advisor_profiles ap ON u.id = ap.user_id
                 WHERE u.id = $1`, [user.id]
            );
            if (profileResult.rows.length > 0) {
                profileData = profileResult.rows[0];
            }
        }
        // (สำหรับ admin หรือ external_professor อาจจะไม่มี profile แยก ก็จะส่งข้อมูลพื้นฐานไป)

        // 4. สร้าง JWT Token
        const payload = {
            userId: user.id,
            role: user.role_name
        };
        // **สำคัญ:** ควรเก็บ 'YOUR_SECRET_KEY' ไว้ใน .env ไฟล์ ไม่ควร hardcode ในโค้ด
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

        // 5. ส่งข้อมูลกลับไปให้ Client
        res.json({
            message: 'Login สำเร็จ!',
            token: token,
            user: {
                id: user.id,
                email: user.email,
                role_name: user.role_name,
                has_signed: user.has_signed,
                ...profileData // รวมข้อมูลโปรไฟล์ที่ดึงมาได้เข้าไปใน object user
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server Error' });
    }
});

// --- API สำหรับเปลี่ยนรหัสผ่าน ---
app.put('/api/users/:userId/change-password', authenticateToken, async (req, res, next) => {
  const { userId } = req.params;
  const { oldPassword, newPassword } = req.body;
  const actorUserId = req.user.userId; // ID ของผู้ใช้ที่ login อยู่ จาก Token

  // ตรวจสอบว่าผู้ใช้ที่ login อยู่ คือเจ้าของบัญชีที่ต้องการเปลี่ยนรหัสผ่าน
  if (parseInt(userId, 10) !== actorUserId) {
    return res.status(403).json({ message: 'ไม่มีสิทธิ์ในการดำเนินการ' });
  }

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ message: 'กรุณากรอกรหัสผ่านปัจจุบันและรหัสผ่านใหม่' });
  }

  const client = await pool.connect();
  try {
    // 1. ดึงรหัสผ่าน (hash) ปัจจุบันของผู้ใช้ออกจากฐานข้อมูล
    const userRes = await client.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบผู้ใช้งาน' });
    }

    const currentHashedPassword = userRes.rows[0].password_hash;

    // 2. เปรียบเทียบรหัสผ่านปัจจุบันที่ผู้ใช้กรอกเข้ามากับรหัสผ่านในฐานข้อมูล
    const isMatch = await bcrypt.compare(oldPassword, currentHashedPassword);
    if (!isMatch) {
      return res.status(401).json({ message: 'รหัสผ่านปัจจุบันไม่ถูกต้อง' });
    }

    // 3. ถ้ารหัสผ่านถูกต้อง ให้เข้ารหัสรหัสผ่านใหม่
    const salt = await bcrypt.genSalt(10);
    const newHashedPassword = await bcrypt.hash(newPassword, salt);

    // 4. อัปเดตรหัสผ่านใหม่ลงในฐานข้อมูล
    await client.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHashedPassword, userId]);

    res.status(200).json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ!' });

  } catch (error) {
    console.error('Error changing password:', error);
    next(error); // ส่ง error ไปให้ error handler กลาง
  } finally {
    client.release();
  }
});

app.post('/api/students', authenticateToken, async (req, res) => {
    // 1. รับข้อมูลทั้งหมดจาก Frontend ตามฟอร์มใหม่
    const { 
        email, password, student_id, 
        prefix_th, first_name_th, middle_name_th, last_name_th,
        prefix_en, first_name_en, middle_name_en, last_name_en,
        phone, gender,
        degree, program_id, major, status_id, 
        entry_year, entry_semester, entry_type, study_plan
    } = req.body;

    if (!email || !password || !student_id || !first_name_th || !last_name_th || !program_id || !status_id) {
        return res.status(400).json({ error: 'กรุณากรอกข้อมูลที่จำเป็นให้ครบถ้วน' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // 2. อัปเดต Query ในตาราง users ให้เพิ่มฟิลด์ใหม่
        const userQuery = `
            INSERT INTO users (
                email, password_hash, role_id,
                prefix_th, first_name_th, middle_name_th, last_name_th,
                prefix_en, first_name_en, middle_name_en, last_name_en,
                gender
            )
            VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id;
        `;
        const userResult = await client.query(userQuery, [
            email, hashedPassword, 
            prefix_th, first_name_th, toNull(middle_name_th), last_name_th,
            prefix_en, first_name_en, toNull(middle_name_en), last_name_en,
            gender
        ]);
        const newUserId = userResult.rows[0].id;

        // 3. อัปเดต Query ในตาราง student_profiles ให้เพิ่มฟิลด์ใหม่
        const profileQuery = `
            INSERT INTO student_profiles (
                user_id, student_id, phone, degree, program_id, major, status_id,
                entry_year, entry_semester, entry_type, study_plan
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
        `;
        await client.query(profileQuery, [
            newUserId, student_id, toNull(phone), degree, program_id, toNull(major), status_id,
            toNull(entry_year), toNull(entry_semester), toNull(entry_type), toNull(study_plan)
        ]);

        await client.query('COMMIT');
        
        res.status(201).json({ message: 'เพิ่มข้อมูลนักศึกษาสำเร็จ!', userId: newUserId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error adding student:', error);
        res.status(500).json({ error: 'Server Error หรืออาจมี Email/รหัสนักศึกษาซ้ำ' });
    } finally {
        client.release();
    }
});

// --- API สำหรับสร้างบัญชีอาจารย์ใหม่ ---
app.post('/api/advisors', authenticateToken, async (req, res, next) => {
    const formData = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. เข้ารหัสผ่าน
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(formData.password, salt);

        // 2. เพิ่มข้อมูลในตาราง users (สมมติ role_id ของ advisor คือ 3)
        const userQuery = `
            INSERT INTO users (
                email, password_hash, role_id, 
                prefix_th, first_name_th, last_name_th,
                prefix_en, first_name_en, last_name_en
            ) VALUES ($1, $2, 3, $3, $4, $5, $6, $7, $8)
            RETURNING id;
        `;
        const userResult = await client.query(userQuery, [
            formData.email, hashedPassword, 
            formData.prefix_th, formData.first_name_th, formData.last_name_th,
            formData.prefix_en, formData.first_name_en, formData.last_name_en,       
        ]);
        const newUserId = userResult.rows[0].id;

        // 3. เพิ่มข้อมูลในตาราง advisor_profiles
        const profileQuery = `
            INSERT INTO advisor_profiles (
                user_id, advisor_id, phone, contact_email, office_location,
                gender, advisor_type, roles, assigned_programs, academic_works
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
        `;
        await client.query(profileQuery, [
            newUserId, formData.advisor_id, formData.phone, formData.contact_email,
            formData.office_location, formData.gender, formData.type,
            formData.roles || [],
            JSON.stringify(formData.assigned_programs || []),
            JSON.stringify(formData.academic_works || [])
        ]);

        await client.query('COMMIT');
        res.status(201).json({ message: 'สร้างบัญชีอาจารย์ใหม่สำเร็จ!', userId: newUserId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error adding advisor:', error);
        // Check for unique constraint violation (e.g., duplicate email or advisor_id)
        if (error.code === '23505') { // PostgreSQL unique violation error code
            res.status(409).json({ message: 'มีอีเมลหรือรหัสอาจารย์นี้ในระบบแล้ว' });
        } else {
            next(error);
        }
    } finally {
        client.release();
    }
});

app.get('/api/programs', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM programs ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: 'Server Error' });
    }
});

// API สำหรับดึงรายชื่อ "ภาควิชา" ทั้งหมด
app.get('/api/departments', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM departments ORDER BY name');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching departments:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับอัปเดตลายเซ็น ---
app.put('/api/users/:userId/signature', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    const { signatureData } = req.body;

    if (!signatureData) {
        return res.status(400).json({ message: 'ไม่พบข้อมูลลายเซ็น' });
    }

    try {
        // 1. สร้างโฟลเดอร์สำหรับเก็บไฟล์ลายเซ็น (ถ้ายังไม่มี)
        const signatureDir = path.join(__dirname, 'uploads', 'signatures');
        if (!fs.existsSync(signatureDir)) {
            fs.mkdirSync(signatureDir, { recursive: true });
        }

        // 2. เตรียมชื่อไฟล์และ Path ที่จะบันทึก
        const fileName = `signature_${userId}_${Date.now()}.png`;
        const filePath = path.join(signatureDir, fileName);
        const fileUrl = `/uploads/signatures/${fileName}`; // Path ที่จะใช้ในเว็บ

        // 3. แปลง Base64 Data URL เป็นไฟล์รูปภาพและบันทึก
        const base64Data = signatureData.replace(/^data:image\/png;base64,/, "");
        fs.writeFileSync(filePath, base64Data, 'base64');

        // 4. อัปเดตฐานข้อมูลในตาราง users
        const query = `
            UPDATE users 
            SET signature_image_url = $1, has_signed = TRUE 
            WHERE id = $2 
            RETURNING id, signature_image_url, has_signed;
        `;
        const result = await pool.query(query, [fileUrl, userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        }

        // 5. ส่งข้อมูลที่อัปเดตแล้วกลับไป
        res.status(200).json({ 
            message: 'บันทึกลายเซ็นสำเร็จ!', 
            data: result.rows[0] 
        });

    } catch (error) {
        console.error('Error saving signature:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับดึงข้อมูลโปรไฟล์ทั้งหมดสำหรับหน้า Home (แก้ไขใหม่ทั้งหมด) ---
app.get('/api/profile/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try {
        // 1. ดึงข้อมูลพื้นฐานของนักศึกษาจาก users และ student_profiles
        const baseProfileQuery = `
            SELECT
                u.id, u.email, u.prefix_th, u.first_name_th, u.last_name_th,
                u.has_signed, u.signature_image_url, r.role_name,
                sp.*, -- ดึงข้อมูลทั้งหมดจาก student_profiles
                p.name as program_name, d.name as department_name, ss.status_name
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN roles r ON u.role_id = r.id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            LEFT JOIN student_statuses ss ON sp.status_id = ss.id
            WHERE u.id = $1;
        `;
        const baseProfileRes = await pool.query(baseProfileQuery, [userId]);
        if (baseProfileRes.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบโปรไฟล์ผู้ใช้' });
        }
        let finalProfile = baseProfileRes.rows[0];

        // 2. ดึงเอกสารที่ "อนุมัติแล้ว" ทั้งหมดของนักศึกษาคนนี้
        // (สมมติว่า status_id = 3 คือ 'อนุมัติ', 'อนุมัติแล้ว', 'ผ่าน')
        const approvedDocsQuery = `
            SELECT document_type_id, form_details, action_date, submission_date
            FROM document_submissions
            WHERE student_user_id = $1 AND status_id = 3
            ORDER BY action_date DESC;
        `;
        const approvedDocsRes = await pool.query(approvedDocsQuery, [userId]);
        const approvedDocs = approvedDocsRes.rows;

        // 3. วนลูปเอกสารที่อนุมัติแล้ว เพื่อสังเคราะห์ข้อมูลลงใน finalProfile
        for (const doc of approvedDocs) {
            const details = doc.form_details || {};
            const approvalDate = doc.action_date || doc.submission_date;

                    switch (doc.document_type_id) {
                case 2: // ฟอร์ม 2: ขออนุมัติหัวข้อและเค้าโครง
                    if (!finalProfile.proposal_status) { 
                        finalProfile.proposal_status = 'อนุมัติแล้ว';
                        finalProfile.proposal_approval_date = approvalDate;
                        // ✅ เพิ่มบรรทัดนี้เข้าไป
                        finalProfile.proposal_defense_date = details.examDate; // สมมติว่าวันที่สอบเก็บใน key ชื่อ 'examDate'
                        finalProfile.thesis_title_th = details.thesis_title_th;
                        finalProfile.thesis_title_en = details.thesis_title_en;
                    }
                    break;
                case 6: // ฟอร์ม 6: ขอสอบวิทยานิพนธ์ขั้นสุดท้าย
                    if (!finalProfile.final_defense_status) {
                        finalProfile.final_defense_status = 'อนุมัติ';
                        finalProfile.final_defense_date = details.examDate;  
                    }
                    break;
                case 7: // ผลสอบภาษาอังกฤษ ป.โท
                    if (!finalProfile.english_master_exam) {
                         finalProfile.english_master_exam = {
                            status: 'ผ่านเกณฑ์',
                            approval_date: approvalDate,
                            exam_type: details.exam_type,
                            scores: details.scores
                        };
                    }
                    break;
                case 8: // ผลสอบภาษาอังกฤษ ป.เอก
                     if (!finalProfile.english_phd_exam) {
                         finalProfile.english_phd_exam = {
                            status: 'ผ่านเกณฑ์',
                            approval_date: approvalDate,
                            exam_type: details.exam_type,
                            scores: details.scores
                        };
                    }
                    break;
                case 9: // ผลสอบวัดคุณสมบัติ (QE)
                    if (!finalProfile.qe_exam) {
                        finalProfile.qe_exam = {
                            status: 'ผ่านเกณฑ์',
                            approval_date: approvalDate,
                            result: details.result
                        };
                    }
                    break;
            }
        }
        
        // 4. ส่งข้อมูลที่รวบรวมและสังเคราะห์เสร็จสมบูรณ์กลับไป
        res.json(finalProfile);

    } catch (error) {
        console.error('Error fetching aggregated profile:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับดึงข้อมูลเอกสารทั้งหมดของนักศึกษา (สำหรับ ProfilePage) (แก้ไขแล้ว) ---
app.get('/api/submissions/student/:userId',authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try {
        const query = `
            SELECT
                ds.id,
                ds.submission_date,
                dt.type_name,
                dst.status_name,
                ds.form_details
            FROM document_submissions ds
            JOIN document_types dt ON ds.document_type_id = dt.id
            JOIN document_statuses dst ON ds.status_id = dst.id
            WHERE ds.student_user_id = $1
            ORDER BY ds.submission_date DESC;
        `;
        const result = await pool.query(query, [userId]);
        res.json(result.rows);
    } catch (error) {
        console.error(`Error fetching submissions for user ID: ${userId}`, error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับดึงรายการ Template ฟอร์มเปล่า ---
app.get('/api/templates', authenticateToken, async (req, res) => {
    try {
        // สมมติว่าคุณมีตาราง form_templates ที่เราเคยสร้างไว้
        const result = await pool.query('SELECT name, docx_path, pdf_path FROM form_templates ORDER BY id');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching templates:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับดึงรายการเอกสารที่อนุมัติแล้วของผู้ใช้ ---
app.get('/api/completed-documents/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try {
        const query = `
            SELECT 
                ds.id,
                dt.type_name,
                ds.submission_date as approved_date -- 1. แก้ไข updated_at เป็น submission_date
            FROM document_submissions ds
            JOIN document_types dt ON ds.document_type_id = dt.id
            WHERE ds.student_user_id = $1 AND ds.status_id = 3 -- สมมติว่า status_id = 3 คือ 'อนุมัติ'
            ORDER BY ds.submission_date DESC; -- 2. แก้ไข updated_at เป็น submission_date
        `;
        const result = await pool.query(query, [userId]);
        
        const documents = result.rows.map(doc => ({
            ...doc,
            title: doc.type_name,
            link: `/path/to/completed/doc_${doc.id}.pdf` // Link สมมติ
        }))
        res.json(documents);
    } catch (error) {
        console.error('Error fetching completed documents:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับอัปเดตเบอร์โทรศัพท์ของนักศึกษา ---
app.put('/api/profile/:userId/phone', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    const { phone } = req.body;

    if (!phone) {
        return res.status(400).json({ message: 'ไม่พบข้อมูลเบอร์โทรศัพท์' });
    }

    try {
        const query = `
            UPDATE student_profiles
            SET phone = $1
            WHERE user_id = $2
            RETURNING user_id, phone;
        `;
        const result = await pool.query(query, [phone, userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบโปรไฟล์นักศึกษา' });
        }

        res.status(200).json({
            message: 'อัปเดตเบอร์โทรศัพท์สำเร็จ!',
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error updating phone number:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับลบลายเซ็น ---
app.delete('/api/users/:userId/signature',authenticateToken, async (req, res) => {
    const { userId } = req.params;

    try {
        // Optional: Find the old file path to delete it from the server's file system
        const oldPathRes = await pool.query('SELECT signature_image_url FROM users WHERE id = $1', [userId]);
        if (oldPathRes.rows.length > 0 && oldPathRes.rows[0].signature_image_url) {
            const oldFilePath = path.join(__dirname, oldPathRes.rows[0].signature_image_url);
            if (fs.existsSync(oldFilePath)) {
                fs.unlinkSync(oldFilePath); // Delete the old file
            }
        }

        // Update the database to remove the reference
        const query = `
            UPDATE users 
            SET signature_image_url = NULL, has_signed = FALSE 
            WHERE id = $1
            RETURNING id, has_signed;
        `;
        const result = await pool.query(query, [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        }

        res.status(200).json({ message: 'ลบลายเซ็นสำเร็จ!' });

    } catch (error) {
        console.error('Error deleting signature:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

app.get('/api/submissions/:submissionId', authenticateToken, async (req, res, next) => {
    try {
        const { submissionId } = req.params;
        
        const submissionQuery = `
            SELECT 
                ds.*, 
                dt.type_name as title, 
                dst.status_name as status,
                u.prefix_th, u.first_name_th, u.last_name_th, u.email,
                sp.student_id, sp.degree, sp.faculty, sp.plan, sp.phone, 
                sp.program_id, sp.department_id,
                sp.main_advisor_id, sp.co_advisor1_id, sp.co_advisor2_id,
                sp.thesis_title_th, sp.thesis_title_en,
                p.name as program_name, d.name as department_name
            FROM document_submissions ds
            JOIN document_types dt ON ds.document_type_id = dt.id
            JOIN document_statuses dst ON ds.status_id = dst.id
            JOIN users u ON ds.student_user_id = u.id
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE ds.id = $1;
        `;
        const submissionResult = await pool.query(submissionQuery, [submissionId]);

        if (submissionResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบเอกสาร' });
        }

        let documentDetail = submissionResult.rows[0];
        const studentUserId = documentDetail.student_user_id;

        // ✅✅✅ ส่วนที่เพิ่มเข้ามาเพื่อดึงข้อมูลเพิ่มเติม ✅✅✅

        // 1. ค้นหาเอกสารที่ "อนุมัติแล้ว" ทั้งหมดของนักศึกษาคนนี้
        const approvedDocsQuery = `
            SELECT document_type_id, form_details, action_date
            FROM document_submissions
            WHERE student_user_id = $1 AND status_id = 3
            ORDER BY action_date DESC;
        `;
        const approvedDocsRes = await pool.query(approvedDocsQuery, [studentUserId]);
        
        // 2. หาข้อมูลจากฟอร์ม 2 ที่อนุมัติแล้ว
        const approvedForm2 = approvedDocsRes.rows.find(doc => doc.document_type_id === 2);

        // 3. ถ้าเจอ ให้เพิ่มข้อมูลลงใน documentDetail
        if (approvedForm2) {
            documentDetail.proposal_approval_date = approvedForm2.action_date;
            if (approvedForm2.form_details && approvedForm2.form_details.committee) {
                documentDetail.proposal_chair_id = approvedForm2.form_details.committee.chair_id;
            }
        }
        // ✅✅✅ จบส่วนที่เพิ่มเข้ามา ✅✅✅

        const [advisorsRes, logsRes] = await Promise.all([
            pool.query(`SELECT u.id, ap.advisor_id, u.prefix_th, u.first_name_th, u.last_name_th FROM users u JOIN advisor_profiles ap ON u.id = ap.user_id`),
            pool.query(`SELECT sl.action, sl.log_comment, sl.log_date, CONCAT(u.prefix_th, u.first_name_th, ' ', u.last_name_th) as actor_name FROM submission_logs sl JOIN users u ON sl.actor_user_id = u.id WHERE sl.submission_id = $1 ORDER BY sl.log_date DESC`, [submissionId])
        ]);

        documentDetail.history = logsRes.rows;

        res.json({
            documentDetail,
            advisors: advisorsRes.rows,
        });
    } catch (error) {
        console.error("Error fetching submission detail:", error);
        next(error);
    }
});

app.get('/api/advisor/profile', authenticateToken, async (req, res) => {
    // ดึง userId จาก Token ที่ authenticateToken ตรวจสอบแล้ว
    const userId = req.user.userId; 
    
    try {
        const profileQuery = `
            SELECT 
                u.id, u.email, u.prefix_th, u.first_name_th, u.last_name_th, u.signature_image_url, 
                ap.advisor_id, ap.academic_position, ap.advisor_type, ap.phone,
                ap.office_location, ap.roles, ap.assigned_programs
            FROM users u
            LEFT JOIN advisor_profiles ap ON u.id = ap.user_id
            WHERE u.id = $1;
        `;
        const profileRes = await pool.query(profileQuery, [userId]);
        
        if (profileRes.rows.length === 0) {
            // หากไม่พบโปรไฟล์อาจารย์
            return res.status(404).json({ message: 'ไม่พบโปรไฟล์อาจารย์' });
        }
        
        const advisorProfile = profileRes.rows[0];
        
        // Logic การแปลง JSONB/Array String (ป้องกัน error หากข้อมูลถูกเก็บเป็น string)
        try {
            if (advisorProfile.roles && typeof advisorProfile.roles === 'string') {
                 advisorProfile.roles = JSON.parse(advisorProfile.roles);
            }
            if (advisorProfile.assigned_programs && typeof advisorProfile.assigned_programs === 'string') {
                 advisorProfile.assigned_programs = JSON.parse(advisorProfile.assigned_programs);
            }
        } catch (e) {
            console.error("JSON parsing failed for roles/programs:", e);
            advisorProfile.roles = Array.isArray(advisorProfile.roles) ? advisorProfile.roles : [];
            advisorProfile.assigned_programs = Array.isArray(advisorProfile.assigned_programs) ? advisorProfile.assigned_programs : [];
        }


        // 2. ดึงชื่อหลักสูตรที่อาจารย์รับผิดชอบ
        let programs = [];
        const programIds = advisorProfile.assigned_programs || [];
        if (programIds.length > 0) {
             const validProgramIds = programIds.filter(id => !isNaN(Number(id))).map(Number);

             if (validProgramIds.length > 0) {
                 const programRes = await pool.query(
                    `SELECT id, name, degree_level FROM programs WHERE id = ANY($1)`, 
                    [validProgramIds]
                 );
                 programs = programRes.rows;
             }
        }

        res.json({ profile: advisorProfile, programs });

    } catch (error) {
        console.error('Error fetching advisor profile:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// =================================================================
//  API Endpoints Admin
// ================================================================

// --- API สำหรับดึงข้อมูล Dashboard ของแอดมิน ---
app.get('/api/admin/all-data', authenticateToken, async (req, res) => {
    try {
        // --- ดึงรายการเอกสารทั้งหมดในระบบ ---
        const docsQuery = `
            SELECT
                ds.id as doc_id,
                dt.type_name as title,
                CONCAT(u.prefix_th, u.first_name_th, ' ', u.last_name_th) as "studentName",
                sp.student_id,
                u.email as student_email,
                ds.submission_date,
                dst.status_name as status
            FROM document_submissions ds
            JOIN users u ON ds.student_user_id = u.id
            LEFT JOIN student_profiles sp ON u.id = sp.user_id
            JOIN document_types dt ON ds.document_type_id = dt.id
            JOIN document_statuses dst ON ds.status_id = dst.id
            ORDER BY ds.submission_date DESC;
        `;
        const docsResult = await pool.query(docsQuery);
        const allDocuments = docsResult.rows;

        // --- คำนวณสถิติทั้งหมดด้วย Query เดียว ---
        const statsQuery = `
            SELECT
                COUNT(*) AS "totalDocs",
                COUNT(*) FILTER (WHERE dst.status_name ILIKE '%อนุมัติ%' OR dst.status_name ILIKE '%ผ่าน%') AS "approved",
                COUNT(*) FILTER (WHERE dst.status_name ILIKE '%ตีกลับ%' OR dst.status_name ILIKE '%ไม่%') AS "rejected",
                COUNT(*) FILTER (WHERE dst.status_name NOT ILIKE '%อนุมัติ%' AND dst.status_name NOT ILIKE '%ผ่าน%' AND dst.status_name NOT ILIKE '%ตีกลับ%' AND dst.status_name NOT ILIKE '%ไม่%') AS "inProgress",
                COUNT(*) FILTER (WHERE dst.status_name = 'รอตรวจสอบ') AS "pendingAdmin",
                COUNT(*) FILTER (WHERE dst.status_name = 'รออาจารย์ที่ปรึกษาอนุมัติ') AS "pendingAdvisor",
                COUNT(*) FILTER (WHERE dst.status_name = 'รออาจารย์บัณฑิตพิเศษอนุมัติ') AS "pendingExternal",
                COUNT(*) FILTER (WHERE dst.status_name = 'รอประธานหลักสูตรอนุมัติ') AS "pendingExecutive"
            FROM document_submissions ds
            JOIN document_statuses dst ON ds.status_id = dst.id;
        `;
        const statsResult = await pool.query(statsQuery);
        const stats = Object.keys(statsResult.rows[0]).reduce((acc, key) => {
            acc[key] = parseInt(statsResult.rows[0][key], 10);
            return acc;
        }, {});

        // --- ส่งข้อมูลทั้งหมดกลับไป ---
        res.json({
            documents: allDocuments,
            stats: stats
        });

    } catch (error) {
        console.error("Error fetching all admin data:", error);
        res.status(500).json({ message: "Server Error" });
    }
});

// --- API สำหรับดึงรายชื่อนักศึกษาทั้งหมด ---
app.get('/api/students', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                u.id as user_id, u.email, u.prefix_th, u.first_name_th, u.last_name_th, u.prefix_en, u.first_name_en, u.last_name_en,
                sp.student_id, sp.degree, sp.faculty, sp.plan, sp.main_advisor_id,sp.phone,p.name as program_name,ss.status_name as status
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN student_statuses ss ON sp.status_id = ss.id
            WHERE u.role_id = 1
            ORDER BY u.first_name_th;
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

app.get('/api/dashboard/student/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  try {
    const userRes = await pool.query(
      'SELECT first_name_th, last_name_th FROM users WHERE id = $1',
      [userId]
    );
    if (userRes.rows.length === 0) {
      return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    }
    const studentName = `${userRes.rows[0].first_name_th} ${userRes.rows[0].last_name_th}`;

    const docsRes = await pool.query(`
      SELECT 
        ds.id,
        ds.submission_date,
        dt.type_name,
        dst.status_name,
        dt.id as document_type_id
      FROM document_submissions ds
      JOIN document_types dt ON ds.document_type_id = dt.id
      JOIN document_statuses dst ON ds.status_id = dst.id
      WHERE ds.student_user_id = $1
      ORDER BY ds.submission_date DESC;
    `, [userId]);

    const allDocuments = docsRes.rows.map(doc => {
      return {
        doc_id: doc.id,
        title: doc.type_name,
        status: doc.status_name,
        submitted_date: doc.submission_date,
        document_type_id: doc.document_type_id
      };
    });
    
    const approvedStates = ['อนุมัติ', 'อนุมัติแล้ว', 'ผ่าน', 'ผ่านเกณฑ์'];
    const rejectedStates = ['ส่งกลับแก้ไข', 'ไม่อนุมัติ', 'ตีกลับ', 'ไม่ผ่านเกณฑ์'];
    
    const approvedDocs = allDocuments.filter(doc => approvedStates.includes(doc.status));
    const rejectedDocs = allDocuments.filter(doc => rejectedStates.includes(doc.status));
    const pendingDocs = allDocuments.filter(doc => !approvedStates.includes(doc.status) && !rejectedStates.includes(doc.status));

    res.json({
      name: studentName,
      counts: {
        pending: pendingDocs.length,
        approved: approvedDocs.length,
        rejected: rejectedDocs.length,
      },
      approvedDocs,
      rejectedDocs,
      allDocuments,
    });

  } catch (error) {
    console.error('Error fetching student dashboard:', error);
    res.status(500).json({ message: 'Server Error' });
  }
});

app.get('/api/admin/student/:studentId', getStudentDetails);
// --- API สำหรับอัปเดตข้อมูลนักศึกษาโดย Admin (ฉบับแก้ไขสมบูรณ์) ---
app.put('/api/admin/student/:studentId', authenticateToken, async (req, res, next) => {
    const { studentId } = req.params; 
    const formData = req.body; 
    
    // Helper function (ควรมีอยู่แล้ว)
    const toNull = (value) => (value === '' || value === undefined ? null : value);
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // เริ่ม Transaction

        // 1. ค้นหา user_id จาก student_id (เหมือนเดิม)
        const userLookupRes = await client.query('SELECT user_id FROM student_profiles WHERE student_id = $1', [studentId]);
        if (userLookupRes.rows.length === 0) {
            return res.status(404).json({ message: `ไม่พบนักศึกษาที่มีรหัส '${studentId}'` });
        }
        const userId = userLookupRes.rows[0].user_id;

        // 2. ✅ อัปเดตตาราง users (เพิ่มฟิลด์ใหม่: ชื่อกลาง, เพศ)
        const userUpdateQuery = `
            UPDATE users SET
                prefix_th = $1, first_name_th = $2, middle_name_th = $3, last_name_th = $4,
                prefix_en = $5, first_name_en = $6, middle_name_en = $7, last_name_en = $8
            WHERE id = $9;
        `;
        await client.query(userUpdateQuery, [
            formData.prefix_th, 
            formData.first_name_th, 
            toNull(formData.middle_name_th), 
            formData.last_name_th,
            formData.prefix_en, 
            formData.first_name_en, 
            toNull(formData.middle_name_en), 
            formData.last_name_en,
            userId
        ]);

        // 3. ✅ อัปเดตตาราง student_profiles (เพิ่มฟิลด์ใหม่ทั้งหมด และคงฟิลด์เก่าไว้)
        const profileUpdateQuery = `
            UPDATE student_profiles SET
                phone = $1, 
                degree = $2, 
                program_id = $3, 
                department_id = $4, 
                status_id = $5,
                major = $6,
                entry_year = $7,
                entry_semester = $8,
                entry_type = $9,
                study_plan = $10,
                main_advisor_id = $11, 
                co_advisor1_id = $12, 
                co_advisor2_id = $13,
                thesis_title_th = $14,
                thesis_title_en = $15,
                proposal_approval_date = $16,
                final_defense_date = $17,
                faculty = $18, 
                plan = $19,
                gender = $20
            WHERE user_id = $21;
        `;
        await client.query(profileUpdateQuery, [
            toNull(formData.phone),                     // $1
            formData.degree,                            // $2
            toNull(formData.program_id),                // $3
            toNull(formData.department_id),             // $4
            formData.status_id,                         // $5
            toNull(formData.major),                     // $6
            toNull(formData.entry_year),                // $7
            toNull(formData.entry_semester),            // $8
            toNull(formData.entry_type),                // $9
            toNull(formData.study_plan),                // $10
            toNull(formData.main_advisor_id),           // $11
            toNull(formData.co_advisor1_id),            // $12
            toNull(formData.co_advisor2_id),            // $13
            toNull(formData.thesis_title_th),           // $14
            toNull(formData.thesis_title_en),           // $15
            toNull(formData.proposal_approval_date),    // $16
            toNull(formData.final_defense_date),        // $17
            toNull(formData.faculty),                   // $18 (ฟิลด์เก่า)
            toNull(formData.plan),                      // $19 (ฟิลด์เก่า)
            formData.gender,                            // $21
            userId                                      // $22
        ]);

        await client.query('COMMIT'); // ยืนยันการเปลี่ยนแปลงทั้งหมด
        
        res.json({ message: 'บันทึกข้อมูลนักศึกษาสำเร็จ!' });

    } catch (error) {
        await client.query('ROLLBACK'); // ยกเลิกการเปลี่ยนแปลงทั้งหมดหากเกิด Error
        console.error(`[ERROR] Failed to update student ${studentId}:`, error);
        next(error); 
    } finally {
        client.release(); 
    }
});

app.get('/api/advisors', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT 
                u.id, 
                ap.advisor_id, 
                u.prefix_th, 
                u.first_name_th, 
                u.last_name_th,
                u.first_name_en,
                u.last_name_en,
                u.email,
                ap.phone,
                ap.gender,
                ap.contact_email,
                ap.office_location, 
                ap.roles,            
                ap.assigned_programs,  
                ap.academic_works,   
                r.role_name,
                --
                CASE
                    WHEN r.role_name = 'executive' OR r.role_name = 'program_chair' THEN 'ผู้บริหาร'
                    WHEN ap.advisor_type LIKE '%ภายนอก%' THEN 'อาจารย์บัณฑิตพิเศษภายนอก'
                    ELSE 'อาจารย์ประจำ'
                END as type
            FROM users u
            LEFT JOIN advisor_profiles ap ON u.id = ap.user_id
            JOIN roles r ON u.role_id = r.id
            WHERE r.role_name != 'student' AND r.role_name != 'admin'
            ORDER BY u.first_name_th;
        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching advisors:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

app.put('/api/advisors/:advisorId', authenticateToken, async (req, res, next) => {
    const { advisorId } = req.params;
    const formData = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. ค้นหา user_id จาก advisor_id
        const userLookup = await client.query(
            'SELECT user_id FROM advisor_profiles WHERE advisor_id = $1',
            [advisorId]
        );
        if (userLookup.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลอาจารย์' });
        }
        const userId = userLookup.rows[0].user_id;

        // 2. อัปเดตตาราง users
        const userUpdateQuery = `
            UPDATE users SET
                prefix_th = $1, first_name_th = $2, last_name_th = $3,
                prefix_en = $4, first_name_en = $5, last_name_en = $6,
                email = $7 
            WHERE id = $8;
        `;
        await client.query(userUpdateQuery, [
            formData.prefix_th, formData.first_name_th, formData.last_name_th,
            formData.prefix_en, formData.first_name_en, formData.last_name_en,
            formData.email, userId
        ]);
        
        // 3. อัปเดตตาราง advisor_profiles
        const profileUpdateQuery = `
            UPDATE advisor_profiles SET
                phone = $1, contact_email = $2, office_location = $3, 
                advisor_type = $4, roles = $5, assigned_programs = $6, 
                academic_works = $7, gender = $8
            WHERE user_id = $9;
        `;
        await client.query(profileUpdateQuery, [
            formData.phone,
            formData.contact_email,
            formData.office_location,
            formData.type,
            formData.roles || [],                                // สำหรับ text[], ส่งเป็น Array ตรงๆ
            JSON.stringify(formData.assigned_programs || []),      // สำหรับ jsonb, ต้อง JSON.stringify
            JSON.stringify(formData.academic_works || []),         // สำหรับ jsonb, ต้อง JSON.stringify
            formData.gender, 
            userId
        ]);

        // (Optional) Logic for updating password if provided
        if (formData.password) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(formData.password, salt);
            await client.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);
        }

        await client.query('COMMIT');
        res.json({ message: 'บันทึกข้อมูลอาจารย์สำเร็จ!' });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error(`[ERROR] Failed to update advisor ${advisorId}:`, error);
        next(error);
    } finally {
        client.release();
    }
});

app.get('/api/advisors/:advisorId/advisees', authenticateToken, async (req, res, next) => {
    // advisorId คือ ID ของอาจารย์ที่กำลังถูกดูข้อมูล (เช่น ADV011)
    const { advisorId } = req.params; 

    try {
        const query = `
            SELECT
                u.id as user_id, 
                sp.student_id,
                u.prefix_th, 
                u.first_name_th, 
                u.last_name_th,
                p.name as program_name, 
                ss.status_name as status,
                sp.degree,
                u.email,
                -- *** CALCULATE THE ADVISOR'S ROLE FOR THIS STUDENT ***
                CASE
                    WHEN sp.main_advisor_id = $1 THEN 'ที่ปรึกษาหลัก'
                    WHEN sp.co_advisor1_id = $1 THEN 'ที่ปรึกษาร่วม คนที่ 1'
                    WHEN sp.co_advisor2_id = $1 THEN 'ที่ปรึกษาร่วม คนที่ 2'
                    ELSE 'ไม่เกี่ยวข้อง' 
                END as advisor_role, -- ชื่อคอลัมน์ใหม่สำหรับแสดงผลบทบาท
                -- ***************************************************
                r.role_name 
            FROM student_profiles sp
            JOIN users u ON sp.user_id = u.id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN student_statuses ss ON sp.status_id = ss.id
            JOIN roles r ON u.role_id = r.id
            WHERE 
                -- ดึงเฉพาะนักศึกษาที่อาจารย์คนนี้เป็นที่ปรึกษา
                sp.main_advisor_id = $1 OR sp.co_advisor1_id = $1 OR sp.co_advisor2_id = $1
            ORDER BY sp.student_id;
        `;

        const result = await pool.query(query, [advisorId]);
        
        // ส่งผลลัพธ์กลับไปที่ Front-end
        res.json(result.rows);

    } catch (error) {
        console.error(`[ERROR] Failed to fetch advisees for advisor ${advisorId}:`, error);
        next(error); // ส่ง Error ให้ Middleware จัดการต่อไป
    }
});

app.get('/api/approvals/my-tasks', authenticateToken, async (req, res) => {
    // (ใน Production ควรมี Middleware ตรวจสอบ Token และดึง userId)
    const approverId = req.user.userId; // สมมติว่าดึง ID ของอาจารย์ที่ login มาได้

    try {
        const tasksQuery = `
            SELECT
                at.id as task_id,
                ds.id as submission_id,
                dt.type_name as document_title,
                ds.submission_date,
                CONCAT(u.prefix_th, u.first_name_th, ' ', u.last_name_th) as student_name
            FROM approval_tasks at
            JOIN document_submissions ds ON at.submission_id = ds.id
            JOIN document_types dt ON ds.document_type_id = dt.id
            JOIN users u ON ds.student_user_id = u.id
            WHERE at.approver_user_id = $1 AND at.status = 'pending'
            ORDER BY ds.submission_date ASC;
        `;
        const result = await pool.query(tasksQuery, [approverId]);
        res.json(result.rows);
    } catch (error) {
        console.error("Error fetching advisor's tasks:", error);
        res.status(500).json({ message: 'Server Error' });
    }
});

app.put('/api/approvals/:taskId', authenticateToken, async (req, res) => {
    const { taskId } = req.params;
    const { newStatus, comment } = req.body;
    const approverId = req.user.userId;

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const updateRes = await client.query(
            `UPDATE public.approval_tasks SET status = $1, comment = $2, updated_at = NOW()
             WHERE id = $3 AND approver_user_id = $4
             RETURNING submission_id`,
            [newStatus, comment, taskId, approverId]
        );
        
        if (updateRes.rows.length === 0) {
            throw new Error('ไม่พบ Task หรือไม่มีสิทธิ์อนุมัติ');
        }
        
        const { submission_id } = updateRes.rows[0];

        const actionText = newStatus === 'approved' ? 'อนุมัติเอกสาร' : 'ตีกลับ/ไม่อนุมัติ';

        await client.query(
            `INSERT INTO public.submission_logs (submission_id, actor_user_id, action, log_comment) VALUES ($1, $2, $3, $4)`,
            [submission_id, approverId, actionText, comment || null]
        );

        if (newStatus === 'approved') {
            const pendingTasksRes = await client.query(
                "SELECT COUNT(*) FROM public.approval_tasks WHERE submission_id = $1 AND status = 'pending'",
                [submission_id]
            );
            
            if (parseInt(pendingTasksRes.rows[0].count, 10) === 0) {
                const submissionRes = await client.query(
                    'SELECT * FROM public.document_submissions WHERE id = $1',
                    [submission_id]
                );
                const submissionData = submissionRes.rows[0];
                const { document_type_id: docTypeId, status_id: currentStatusId } = submissionData;
                let nextStatusId;

                // --- Workflow การเปลี่ยนสถานะ ---
                if (docTypeId === 1) {
                    if (currentStatusId === 6) { nextStatusId = 10; } else if (currentStatusId === 10) { nextStatusId = 13; } else if (currentStatusId === 13) { nextStatusId = 3; }
                }
                else if (docTypeId === 2 || docTypeId === 6) {
                    if (currentStatusId === 12) { nextStatusId = 9; } else if (currentStatusId === 9) { nextStatusId = 8; } else if (currentStatusId === 8) { nextStatusId = 14; } else if (currentStatusId === 14) { nextStatusId = 15; } else if (currentStatusId === 15) { nextStatusId = 16; } else if (currentStatusId === 16) { nextStatusId = 17; } else if (currentStatusId === 17) { nextStatusId = 10; } else if (currentStatusId === 10) { nextStatusId = 13; } else if (currentStatusId === 13) { nextStatusId = 3; }
                }
                else if (docTypeId === 3) {
                    if (currentStatusId === 12) { nextStatusId = 9; } else if (currentStatusId === 9) { nextStatusId = 13; } else if (currentStatusId === 13) { nextStatusId = 3; }
                }
                else if (docTypeId === 4) {
                    if (currentStatusId === 11) { nextStatusId = 7; } else if (currentStatusId === 7) { nextStatusId = 13; } else if (currentStatusId === 13) { nextStatusId = 3; }
                }
                else if (docTypeId === 5) {
                    if (currentStatusId === 11) { nextStatusId = 13; } else if (currentStatusId === 13) { nextStatusId = 3; }
                }

                if (nextStatusId) {
                    await client.query(
                        'UPDATE public.document_submissions SET status_id = $1, action_date = NOW() WHERE id = $2',
                        [nextStatusId, submission_id]
                    );
                    const statusNameRes = await client.query('SELECT status_name FROM public.document_statuses WHERE id = $1', [nextStatusId]);
                    const nextStatusName = statusNameRes.rows[0]?.status_name;
                    await client.query(
                        `INSERT INTO public.submission_logs (submission_id, actor_user_id, action, log_comment) VALUES ($1, $2, $3, $4)`,
                        [submission_id, approverId, `ระบบเปลี่ยนสถานะเป็น "${nextStatusName}"`, 'อนุมัติครบตามขั้นตอน']
                    );
                    const getUserIdFromAdvisorId = async (advisorId) => {
                        if (!advisorId) return null;
                        const res = await client.query('SELECT user_id FROM public.advisor_profiles WHERE advisor_id = $1', [advisorId]);
                        return res.rows.length > 0 ? res.rows[0].user_id : null;
                    };
                    const getUserIdsByRole = async (roleName) => {
                        const res = await client.query(`SELECT u.id FROM public.users u JOIN public.roles r ON u.role_id = r.id WHERE r.role_name = $1`,[roleName]);
                        return res.rows.map(row => row.id);
                    };

                    let nextApproverUserIds = [];
                    const formDetails = submissionData.form_details || {};
                    const committee = formDetails.committee || {};
                    
                    switch (nextStatusName) {
                        case 'รออาจารย์ที่ปรึกษาอนุมัติ': {
                            const studentProfile = await client.query(`SELECT main_advisor_id, co_advisor1_id FROM public.student_profiles WHERE user_id = $1`, [submissionData.student_user_id]);
                            const advisors = studentProfile.rows[0] || {};
                            const advisorIds = [advisors.main_advisor_id, advisors.co_advisor1_id].filter(Boolean);
                            for (const adId of advisorIds) {
                                const uId = await getUserIdFromAdvisorId(adId);
                                if (uId) nextApproverUserIds.push(uId);
                            }
                            break;
                        }
                        case 'รออาจารย์ที่ปรึกษาหลักอนุมัติ': {
                            const studentProfile = await client.query(`SELECT main_advisor_id FROM public.student_profiles WHERE user_id = $1`, [submissionData.student_user_id]);
                            const mainAdvisorId = studentProfile.rows[0]?.main_advisor_id;
                            const userId = await getUserIdFromAdvisorId(mainAdvisorId);
                            if (userId) nextApproverUserIds.push(userId);
                            break;
                        }
                        case 'รออาจารย์ที่ปรึกษา (3 ท่าน) อนุมัติ': {
                            const profileRes = await client.query(
                                `SELECT main_advisor_id, co_advisor1_id, co_advisor2_id FROM public.student_profiles WHERE user_id = $1`,
                                [submissionData.student_user_id] // <-- แก้ไข: ใช้ submissionData
                            );
                            const advisors = profileRes.rows[0] || {};
                            const advisorIds = [
                                advisors.main_advisor_id,
                                advisors.co_advisor1_id,
                                advisors.co_advisor2_id
                            ].filter(Boolean);
                            for (const advisorId of advisorIds) {
                                const userId = await getUserIdFromAdvisorId(advisorId);
                                if (userId) nextApproverUserIds.push(userId); // <-- แก้ไข: ใช้ nextApproverUserIds
                            }
                            break;
                        }
                        case 'รอประธานกรรมการสอบอนุมัติ': {
                            const profileRes = await client.query(`SELECT proposal_chair_id FROM public.student_profiles WHERE user_id = $1`, [submissionData.student_user_id]);
                            const studentProfile = profileRes.rows[0] || {};
                            const chairId = studentProfile.proposal_chair_id || committee.chair_id;
                            const userId = await getUserIdFromAdvisorId(chairId);
                            if (userId) nextApproverUserIds.push(userId);
                            break;
                        }
                        
                        case 'รอคณะกรรมการสอบอนุมัติ': { // <-- แก้ไข: รวม Case ที่ซ้ำ และแก้ Logic
                            const profileRes = await client.query(`SELECT proposal_member5_id FROM public.student_profiles WHERE user_id = $1`, [submissionData.student_user_id]);
                            const studentProfile = profileRes.rows[0] || {};
                            const memberIds = [
                                studentProfile.proposal_member5_id || committee.member5_id
                            ].filter(Boolean);
                    
                            for (const memberId of memberIds) {
                                const userId = await getUserIdFromAdvisorId(memberId);
                                if (userId) nextApproverUserIds.push(userId);
                            }
                            break;
                        }
                        
                        case 'รออาจารย์ภายนอกอนุมัติ': { // <-- แก้ไข: เพิ่มการหาข้อมูลจาก student_profiles
                            const profileRes = await client.query(`SELECT proposal_reserve_external_id FROM public.student_profiles WHERE user_id = $1`, [submissionData.student_user_id]);
                            const studentProfile = profileRes.rows[0] || {};
                            const externalAdvisorIds = [];
                            const externalIdFromProfile = studentProfile.proposal_reserve_external_id;

                            if (externalIdFromProfile) {
                                externalAdvisorIds.push(externalIdFromProfile);
                            } else if (Array.isArray(formDetails.external_advisor_ids)) {
                                externalAdvisorIds.push(...formDetails.external_advisor_ids);
                            } else if (formDetails.external_advisor_id) {
                                externalAdvisorIds.push(formDetails.external_advisor_id);
                            }

                            for (const advisorId of externalAdvisorIds) {
                                const userId = await getUserIdFromAdvisorId(advisorId);
                                if (userId) nextApproverUserIds.push(userId);
                            }
                            break;
                        }

                        case 'รออาจารย์สำรองภายในอนุมัติ': {
                            const profileRes = await client.query(`SELECT proposal_reserve_internal_id FROM public.student_profiles WHERE user_id = $1`, [submissionData.student_user_id]);
                            const studentProfile = profileRes.rows[0] || {};
                            const reserveInternalId = studentProfile.proposal_reserve_internal_id || committee.reserve_internal_id;
                            const userId = await getUserIdFromAdvisorId(reserveInternalId);
                            if (userId) nextApproverUserIds.push(userId);
                            break;
                        }
                        case 'รออาจารย์สำรองภายนอกอนุมัติ': {
                            const profileRes = await client.query(`SELECT proposal_reserve_external_id FROM public.student_profiles WHERE user_id = $1`, [submissionData.student_user_id]);
                            const studentProfile = profileRes.rows[0] || {};
                            const reserveExternalId = studentProfile.proposal_reserve_external_id || committee.reserve_external_id;
                            const userId = await getUserIdFromAdvisorId(reserveExternalId);
                            if (userId) nextApproverUserIds.push(userId);
                            break;
                        }

                        // --- Role-based approvals ---
                        case 'รอคณบดีอนุมัติ':
                            nextApproverUserIds = await getUserIdsByRole('executive');
                            break;
                        case 'รอเจ้าหน้าที่ยืนยัน':
                            nextApproverUserIds = await getUserIdsByRole('admin');
                            break;
                        case 'รอประธานหลักสูตรอนุมัติ':
                            nextApproverUserIds = await getUserIdsByRole('program_chair');
                            break;
                        case 'รอผู้ช่วยคณบดีอนุมัติ':
                            nextApproverUserIds = await getUserIdsByRole('assistant_rector');
                            break;
                    }

                    if (nextApproverUserIds.length > 0) {
                        for (const nextApproverId of nextApproverUserIds) {
                            await client.query(
                                'INSERT INTO public.approval_tasks (submission_id, approver_user_id, status) VALUES ($1, $2, $3)',
                                [submission_id, nextApproverId, 'pending']
                            );
                        }
                    }
                }
            }
        }

        await client.query('COMMIT');
        res.json({ message: 'ดำเนินการสำเร็จ' });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error processing approval:", error);
        res.status(500).json({ message: error.message || 'Server Error' });
    } finally {
        client.release();
    }
});

// --- API สำหรับนักศึกษา Re-submit เอกสารที่ถูกตีกลับ (ใหม่!) ---
app.put('/api/submissions/:submissionId/resubmit', authenticateToken, async (req, res, next) => {
    // กำหนด Status ID 18 เป็นสถานะรอ Admin ตรวจสอบหลัง Re-submit
    const NEXT_ADMIN_REVIEW_STATUS_ID = 18; 
    
    const { submissionId } = req.params;
    const student_user_id = req.user.userId;
    // ข้อมูลฟอร์มที่อัปเดตใหม่, student_comment (ถ้ามี)
    const { form_details, student_comment } = req.body; 

    if (!form_details) {
        return res.status(400).json({ message: 'ข้อมูลฟอร์มไม่ครบถ้วนสำหรับการ Re-submit' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. ตรวจสอบสิทธิ์ (ต้องเป็นเจ้าของเอกสาร)
        const currentDocRes = await client.query('SELECT status_id FROM document_submissions WHERE id = $1 AND student_user_id = $2', [submissionId, student_user_id]);
        if (currentDocRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'ไม่พบเอกสารหรือไม่มีสิทธิ์ดำเนินการ' });
        }
        
        // 2. ดึงชื่อสถานะใหม่
        const statusNameRes = await client.query('SELECT status_name FROM document_statuses WHERE id = $1', [NEXT_ADMIN_REVIEW_STATUS_ID]);
        if (statusNameRes.rows.length === 0) {
             await client.query('ROLLBACK');
             throw new Error('Status ID 18 not found.');
        }
        const nextStatusName = statusNameRes.rows[0].status_name;


        // 3. อัปเดตเอกสารด้วยสถานะใหม่
        await client.query(
            `UPDATE document_submissions SET 
                status_id = $1, 
                student_comment = $2, 
                form_details = $3, 
                submission_date = NOW(), 
                action_date = NULL -- ล้าง action_date เพื่อเริ่ม Workflow ใหม่
             WHERE id = $4`,
            [NEXT_ADMIN_REVIEW_STATUS_ID, student_comment, JSON.stringify(form_details), submissionId]
        );
        
        // 4. ล้าง Tasks เดิมที่ค้างอยู่ทั้งหมด
        await client.query(`DELETE FROM approval_tasks WHERE submission_id = $1`, [submissionId]);


        // 5. สร้าง Log ใหม่
        await client.query(
            `INSERT INTO submission_logs (submission_id, actor_user_id, action, log_comment) 
             VALUES ($1, $2, $3, $4)`,
            [submissionId, student_user_id, `นักศึกษาส่งเอกสารกลับมาแก้ไขใหม่`, `เปลี่ยนสถานะเป็น "${nextStatusName}"`]
        );

        // 6. สร้าง Approval Task ใหม่สำหรับ Admin ทันที
        const getUserIdsByRole = async (roleName) => {
            const res = await client.query(
                `SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.role_name = $1`,
                [roleName]
            );
            return res.rows.map(row => row.id);
        };
        
        const approverUserIds = await getUserIdsByRole('admin'); // สมมติว่า Admin Role Name คือ 'admin'
        for (const approverId of approverUserIds) {
            await client.query(
                'INSERT INTO approval_tasks (submission_id, approver_user_id, status) VALUES ($1, $2, $3)',
                [submissionId, approverId, 'pending']
            );
        }

        await client.query('COMMIT');
        res.status(200).json({ message: 'ส่งเอกสารกลับมาตรวจสอบใหม่สำเร็จ!', submissionId });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error on Re-submit:', error);
        next(error);
    } finally {
        client.release();
    }
});


app.put('/api/documents/:id/status', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status_name, reason } = req.body; // status_name คือ newStatus ที่ส่งมาจาก Frontend

  try {
    // หา status_id จาก status_name
    const statusResult = await pool.query(
      'SELECT id FROM document_statuses WHERE status_name = $1',
      [status_name]
    );

    if (statusResult.rows.length === 0) {
      return res.status(400).json({ message: 'Invalid status name provided.' });
    }
    const new_status_id = statusResult.rows[0].id;

    // อัปเดตสถานะใน document_submissions
    await pool.query(
      'UPDATE document_submissions SET status_id = $1, admin_comment = $2 WHERE id = $3',
      [new_status_id, reason, id]
    );

    // คุณอาจจะต้องมี Logic เพิ่มเติมสำหรับการส่ง Notification หรือ Logic การเปลี่ยนสถานะตาม Workflow
    // เช่น ถ้า new_status_id เป็น PENDING_ADVISOR คุณอาจจะต้องส่ง Notification ให้อาจารย์ที่ปรึกษา

    res.status(200).json({ message: 'Document status updated successfully.' });
  } catch (error) {
    console.error('Error updating document status:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/submissions/:submissionId/status', authenticateToken, async (req, res, next) => {
    const { submissionId } = req.params;
    const { status_name, admin_comment, actor_user_id } = req.body;
    const client = await pool.connect();

    // --- Helper Functions defined inside the handler to ensure scope ---
    const getUserIdFromAdvisorId = async (advisorId) => {
        if (!advisorId) return null;
        const res = await client.query('SELECT user_id FROM advisor_profiles WHERE advisor_id = $1', [advisorId]);
        return res.rows.length > 0 ? res.rows[0].user_id : null;
    };

    const getUserIdsByRole = async (roleName) => {
        const res = await client.query(
            `SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id WHERE r.role_name = $1`,
            [roleName]
        );
        return res.rows.map(row => row.id);
    };
    // -----------------------------------------------------------------

    try {
        await client.query('BEGIN');

        const statusRes = await client.query('SELECT id FROM document_statuses WHERE status_name = $1', [status_name]);
        if (statusRes.rows.length === 0) {
            throw new Error(`ไม่พบสถานะชื่อ: "${status_name}"`);
        }
        const newStatusId = statusRes.rows[0].id;

        const updatedDoc = await client.query(
            `UPDATE document_submissions SET status_id = $1, admin_comment = $2, action_date = NOW() WHERE id = $3 RETURNING *;`,
            [newStatusId, admin_comment, submissionId]
        );
        if (updatedDoc.rows.length === 0) {
            throw new Error('ไม่พบเอกสาร');
        }
        
        const docData = updatedDoc.rows[0];
        let approverUserIds = [];
        const formDetails = docData.form_details || {};
        const committee = formDetails.committee || {};
        
        // --- Workflow Logic for creating next approval tasks ---
        switch(status_name) {
            case 'รอเจ้าหน้าที่ตรวจสอบข้อมูล': {
                approverUserIds = await getUserIdsByRole('admin'); 
                break;
            }

            case 'รออาจารย์ที่ปรึกษาหลักอนุมัติ': {
                let mainAdvisorId;
                if (docData.document_type_id === 1) { 
                    mainAdvisorId = formDetails.main_advisor_id;
                } else { 
                    const profileRes = await client.query(`SELECT main_advisor_id FROM student_profiles WHERE user_id = $1`, [docData.student_user_id]);
                    mainAdvisorId = profileRes.rows[0]?.main_advisor_id;
                }
                const userId = await getUserIdFromAdvisorId(mainAdvisorId);
                if (userId) approverUserIds.push(userId);
                break;
            }

            case 'รออาจารย์ที่ปรึกษาอนุมัติ': {
                const advisorIds = [];
                if (docData.document_type_id === 1) {
                    if (formDetails.main_advisor_id) advisorIds.push(formDetails.main_advisor_id);
                    if (formDetails.co_advisor_id) advisorIds.push(formDetails.co_advisor_id);
                } else {
                    const profileRes = await client.query(`SELECT main_advisor_id, co_advisor1_id FROM student_profiles WHERE user_id = $1`, [docData.student_user_id]);
                    const advisors = profileRes.rows[0] || {};
                    if(advisors.main_advisor_id) advisorIds.push(advisors.main_advisor_id);
                    if(advisors.co_advisor1_id) advisorIds.push(advisors.co_advisor1_id);
                }

                for (const advisorId of advisorIds) {
                    const userId = await getUserIdFromAdvisorId(advisorId);
                    if (userId) approverUserIds.push(userId);
                }
                break;
            }

            case 'รออาจารย์ที่ปรึกษา (3 ท่าน) อนุมัติ': {
                const profileRes = await client.query(
                    `SELECT main_advisor_id, co_advisor1_id FROM student_profiles WHERE user_id = $1`,
                    [docData.student_user_id]
                );
                const officialAdvisors = profileRes.rows[0] || {};
                const coAdvisor2Id = committee.co_advisor2_id;

                const advisorStringIds = [
                    officialAdvisors.main_advisor_id,
                    officialAdvisors.co_advisor1_id,
                    coAdvisor2Id
                ].filter(Boolean);

                for (const advisorId of advisorStringIds) {
                    const userId = await getUserIdFromAdvisorId(advisorId);
                    if (userId) approverUserIds.push(userId);
                }
                break;
            }
            case 'รอคณะกรรมการสอบอนุมัติ': {
                const committeeMemberIds = [
                    committee.co_advisor2_id,
                    committee.member5_id
                ].filter(Boolean);
                for (const memberId of committeeMemberIds) {
                    const userId = await getUserIdFromAdvisorId(memberId);
                    if (userId) approverUserIds.push(userId);
                }
                break;
            }
            case 'รอประธานกรรมการสอบอนุมัติ': {
                const userId = await getUserIdFromAdvisorId(committee.chair_id);
                if (userId) approverUserIds.push(userId);
                break;
            }
            case 'รออาจารย์สำรองภายในอนุมัติ': {
                const userId = await getUserIdFromAdvisorId(committee.reserve_internal_id);
                if (userId) approverUserIds.push(userId);
                break;
            }
            case 'รออาจารย์สำรองภายนอกอนุมัติ': {
                const userId = await getUserIdFromAdvisorId(committee.reserve_external_id);
                if (userId) approverUserIds.push(userId);
                break;
            }
              case 'รออาจารย์ภายนอกอนุมัติ': {
                const externalAdvisorId = formDetails.external_advisor_id; 
                const userId = await getUserIdFromAdvisorId(externalAdvisorId);
                if (userId) approverUserIds.push(userId);
                break;
            }
            case 'รอประธานหลักสูตรอนุมัติ': 
                approverUserIds = await getUserIdsByRole('program_chair');
                break;
            case 'รอผู้ช่วยอธิการบดีอนุมัติ':
                approverUserIds = await getUserIdsByRole('assistant_rector');
                break;
            case 'รออธิการบดีอนุมัติ':
                approverUserIds = await getUserIdsByRole('executive');
                break;
        }

        // Create the actual approval tasks if any approvers were found
        if (approverUserIds.length > 0) {
            for (const approverId of approverUserIds) {
                await client.query(
                    'INSERT INTO approval_tasks (submission_id, approver_user_id, status) VALUES ($1, $2, $3)',
                    [submissionId, approverId, 'pending']
                );
            }
        }
        
        // --- Logic to update student_profiles upon final approval ---
        if (status_name === 'อนุมัติ') {
            
            // Logic for English Exam results (Doc Type 7 or 8)
            if (docData.document_type_id === 7 || docData.document_type_id === 8) {
                const scoreEntries = Object.entries(formDetails)
                    .filter(([key]) => !['exam_type', 'exam_date', 'files', 'scores', 'result', 'student_comment'].includes(key));
                
                const totalScoreEntry = scoreEntries.find(([key]) => key.includes('total_score') || key.includes('overall_band') || key.includes('score'));
                const finalScore = totalScoreEntry ? totalScoreEntry[1] : null;
                const finalStatus = 'ผ่านเกณฑ์';
                
                await client.query(
                    `UPDATE student_profiles 
                       SET 
                         english_test_type = $1, 
                         english_test_date = $2, 
                         english_test_score = $3, 
                         english_test_status = $4
                       WHERE user_id = $5`,
                    [
                        formDetails.exam_type || null, 
                        formDetails.exam_date || null, 
                        finalScore, 
                        finalStatus,
                        docData.student_user_id
                    ]
                );
            }

            // Logic for Form 1 (Assigning advisors)
              if (docData.document_type_id === 1) { 
                await client.query(
                    `UPDATE student_profiles SET main_advisor_id = $1, co_advisor1_id = $2 WHERE user_id = $3`,
                    [formDetails.main_advisor_id, formDetails.co_advisor_id || null, docData.student_user_id]
                );
            }
            // Logic for Form 2 (Assigning committee and thesis titles)
              if (docData.document_type_id === 2) { 
                await client.query(
                    `UPDATE student_profiles 
                       SET 
                         co_advisor2_id = $1, 
                         thesis_title_th = $2,
                         thesis_title_en = $3,
                         proposal_chair_id = $4,
                         proposal_member5_id = $5,
                         proposal_reserve_internal_id = $6,
                         proposal_reserve_external_id = $7,
                         proposal_approval_date = NOW()
                       WHERE user_id = $8`,
                    [
                        committee.co_advisor2_id || null, 
                        formDetails.thesis_title_th,
                        formDetails.thesis_title_en,
                        committee.chair_id,
                        committee.member5_id,
                        committee.reserve_internal_id,
                        committee.reserve_external_id,
                        docData.student_user_id
                    ]
                );
            }
            // Logic for Form 6 (Setting final defense date)
              if (docData.document_type_id === 6) { 
                  await client.query(
                    `UPDATE student_profiles SET final_defense_date = $1 WHERE user_id = $2`,
                    [formDetails.examDate, docData.student_user_id] 
                );
            }
        }

        // Log this action
        await client.query(
            `INSERT INTO submission_logs (submission_id, actor_user_id, action, log_comment) VALUES ($1, $2, $3, $4);`,
            [submissionId, actor_user_id, `เปลี่ยนสถานะเป็น "${status_name}"`, admin_comment || null]
        );
        
        await client.query('COMMIT');
        res.status(200).json({ message: 'อัปเดตสถานะสำเร็จ!', data: docData });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('--- TRANSACTION FAILED ---', error);
        next(error);
    } finally {
        client.release();
    }
});


// --- API สำหรับลบนักศึกษา ---
app.delete('/api/students/:studentId', authenticateToken, async (req, res, next) => {
    const { studentId } = req.params;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. ค้นหา user_id จาก student_id ก่อน
        const userLookup = await client.query(
            'SELECT user_id FROM student_profiles WHERE student_id = $1',
            [studentId]
        );

        if (userLookup.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบนักศึกษาที่ระบุ' });
        }
        const userId = userLookup.rows[0].user_id;

        // 2. ลบข้อมูลที่เกี่ยวข้องก่อน (ถ้ามี) เช่น document_submissions
        // (เพื่อป้องกัน Foreign Key Error)
        await client.query('DELETE FROM document_submissions WHERE student_user_id = $1', [userId]);

        // 3. ลบข้อมูลจากตาราง student_profiles
        await client.query('DELETE FROM student_profiles WHERE user_id = $1', [userId]);

        // 4. ลบข้อมูลจากตาราง users เป็นลำดับสุดท้าย
        await client.query('DELETE FROM users WHERE id = $1', [userId]);

        await client.query('COMMIT');
        res.status(200).json({ message: `ลบข้อมูลนักศึกษา ${studentId} สำเร็จ` });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error(`Error deleting student ${studentId}:`, error);
        next(error); // ส่งไปให้ error handler
    } finally {
        client.release();
    }
});

// --- API สำหรับสร้างภาควิชาใหม่ ---
app.post('/api/departments', authenticateToken, async (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ message: 'กรุณากรอกชื่อภาควิชา' });
    }
    try {
        const result = await pool.query(
            'INSERT INTO departments (name) VALUES ($1) RETURNING *', 
            [name]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error adding department:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับแก้ไขชื่อภาควิชา ---
app.put('/api/departments/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ message: 'กรุณากรอกชื่อภาควิชา' });
    }
    try {
        const result = await pool.query(
            'UPDATE departments SET name = $1 WHERE id = $2 RETURNING *', 
            [name, id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบภาควิชาที่ต้องการแก้ไข' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating department:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับลบภาควิชา ---
app.delete('/api/departments/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM departments WHERE id = $1 RETURNING *', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'ไม่พบภาควิชาที่ต้องการลบ' });
        }
        res.status(200).json({ message: 'ลบภาควิชาสำเร็จ' });
    } catch (error) {
        console.error('Error deleting department:', error);
        // เพิ่มการตรวจสอบ Foreign Key Error
        if (error.code === '23503') { 
            return res.status(409).json({ message: 'ไม่สามารถลบภาควิชานี้ได้ เนื่องจากมีข้อมูลอื่นเชื่อมโยงอยู่' });
        }
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับสร้างหลักสูตรใหม่ (แก้ไขแล้ว) ---
app.post('/api/programs', authenticateToken, async (req, res) => {
    // 1. รับ degree_level และ name จาก body
    const { name, degree_level } = req.body;
    if (!name || !degree_level) {
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
    }
    try {
        // 2. เพิ่ม degree_level เข้าไปในคำสั่ง INSERT
        const result = await pool.query(
            'INSERT INTO programs (name, degree_level) VALUES ($1, $2) RETURNING *',
            [name, degree_level]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error adding program:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับแก้ไขชื่อหลักสูตร (แก้ไขแล้ว) ---
app.put('/api/programs/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    // 1. รับ degree_level และ name จาก body
    const { name, degree_level } = req.body;
    if (!name || !degree_level) {
        return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
    }
    try {
        // 2. เพิ่ม degree_level เข้าไปในคำสั่ง UPDATE
        const result = await pool.query(
            'UPDATE programs SET name = $1, degree_level = $2 WHERE id = $3 RETURNING *',
            [name, degree_level, id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบหลักสูตรที่ต้องการแก้ไข' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating program:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับลบหลักสูตร ---
app.delete('/api/programs/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM programs WHERE id = $1 RETURNING *', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'ไม่พบหลักสูตรที่ต้องการลบ' });
        }
        res.status(200).json({ message: 'ลบหลักสูตรสำเร็จ' });
    } catch (error) {
        console.error('Error deleting program:', error);
        if (error.code === '23503') {
            return res.status(409).json({ message: 'ไม่สามารถลบหลักสูตรนี้ได้ เนื่องจากมีข้อมูลอื่นเชื่อมโยงอยู่' });
        }
        res.status(500).json({ message: 'Server Error' });
    }
});


// --- API สำหรับลบภาควิชา ---
app.delete('/api/departments/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM departments WHERE id = $1 RETURNING *', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ message: 'ไม่พบภาควิชาที่ต้องการลบ' });
        }
        res.status(200).json({ message: 'ลบภาควิชาสำเร็จ' });
    } catch (error) {
        console.error('Error deleting department:', error);
        // เพิ่มการตรวจสอบ Foreign Key Error
        if (error.code === '23503') { 
            return res.status(409).json({ message: 'ไม่สามารถลบภาควิชานี้ได้ เนื่องจากมีข้อมูลอื่นเชื่อมโยงอยู่' });
        }
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับลบอาจารย์ ---
app.delete('/api/advisors/:advisorId', authenticateToken, async (req, res, next) => {
    // ดึง advisorId จาก URL parameter
    const { advisorId } = req.params;
    // (ใน Production ควรมีการตรวจสอบ Role เพิ่มเติมว่าผู้ใช้เป็น Admin หรือไม่)

    const client = await pool.connect();

    try {
        // เริ่มต้น Transaction
        await client.query('BEGIN');

        // 1. ค้นหา user_id จาก advisor_id ที่ระบุ
        const userLookup = await client.query(
            'SELECT user_id FROM advisor_profiles WHERE advisor_id = $1',
            [advisorId]
        );

        if (userLookup.rows.length === 0) {
            // ถ้าไม่พบ advisor_id นี้ ให้ส่ง 404 Not Found
            return res.status(404).json({ message: 'ไม่พบข้อมูลอาจารย์ที่ระบุ' });
        }
        const userId = userLookup.rows[0].user_id;

        // 2. (สำคัญ) อัปเดตข้อมูลในตาราง student_profiles
        // ตั้งค่า ID ของอาจารย์ที่ถูกลบให้เป็น NULL ในโปรไฟล์ของนักศึกษาทุกคน
        // เพื่อป้องกัน Foreign Key Constraint Error
        await client.query(
            `UPDATE student_profiles SET 
                main_advisor_id = CASE WHEN main_advisor_id = $1 THEN NULL ELSE main_advisor_id END,
                co_advisor1_id = CASE WHEN co_advisor1_id = $1 THEN NULL ELSE co_advisor1_id END,
                co_advisor2_id = CASE WHEN co_advisor2_id = $1 THEN NULL ELSE co_advisor2_id END
            WHERE main_advisor_id = $1 OR co_advisor1_id = $1 OR co_advisor2_id = $1`,
            [advisorId]
        );
        
        // 3. (Optional แต่แนะนำ) ลบ Tasks ที่ค้างอยู่ของอาจารย์คนนี้
        await client.query('DELETE FROM approval_tasks WHERE approver_user_id = $1', [userId]);


        // 4. ลบข้อมูลจากตาราง advisor_profiles
        await client.query('DELETE FROM advisor_profiles WHERE user_id = $1', [userId]);

        // 5. ลบข้อมูลจากตาราง users เป็นลำดับสุดท้าย
        await client.query('DELETE FROM users WHERE id = $1', [userId]);

        // หากทุกอย่างสำเร็จ ให้ Commit Transaction
        await client.query('COMMIT');
        
        // ส่งข้อความยืนยันกลับไป
        res.status(200).json({ message: `ลบข้อมูลอาจารย์ ${advisorId} สำเร็จ` });

    } catch (error) {
        // หากเกิดข้อผิดพลาด ให้ Rollback Transaction
        await client.query('ROLLBACK');
        console.error(`Error deleting advisor ${advisorId}:`, error);
        next(error); // ส่ง Error ไปให้ Middleware จัดการ
    } finally {
        // คืน Connection กลับสู่ Pool ไม่ว่าจะสำเร็จหรือล้มเหลว
        client.release();
    }
});

// =================================================================
//  API Endpoints From
// =================================================================

// --- API สำหรับดึงข้อมูลที่จำเป็นสำหรับ Form 1 ---
app.get('/api/form1/data/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try {
        // 1. ดึงข้อมูลโปรไฟล์ของนักศึกษาที่ล็อกอินอยู่
        const studentQuery = `
            SELECT 
                u.id, u.email, u.prefix_th, u.first_name_th, u.last_name_th,
                sp.student_id, sp.degree, sp.faculty, sp.study_plan, sp.phone,
                p.name as program_name,
                d.name as department_name
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE u.id = $1;
        `;
        const studentResult = await pool.query(studentQuery, [userId]);
        if (studentResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลนักศึกษา' });
        }

        // 2. ดึงรายชื่ออาจารย์ทั้งหมดสำหรับ Dropdown
        const advisorsQuery = `
            SELECT u.id, ap.advisor_id, u.prefix_th, u.first_name_th, u.last_name_th
            FROM users u
            JOIN advisor_profiles ap ON u.id = ap.user_id
            WHERE u.role_id = 3 ORDER BY u.first_name_th;
        `;
        const advisorsResult = await pool.query(advisorsQuery);
        
        // 3. ส่งข้อมูลทั้งสองส่วนกลับไป
        res.json({
            studentInfo: studentResult.rows[0],
            advisors: advisorsResult.rows
        });

    } catch (error) {
        console.error('Error fetching data for Form 1:', error);
        res.status(500).json({ message: 'Server Error' });
    }
});

// --- API สำหรับการยื่น Form 1 ---
app.post('/api/submissions/form1', authenticateToken, async (req, res) => {
    const student_user_id = req.user.userId; 
    const { main_advisor_id, co_advisor_id, student_comment } = req.body;

    if (!student_user_id || !main_advisor_id) {
        return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // จัดเก็บข้อมูลเฉพาะของฟอร์มลงใน JSONB
        const formDetails = {
            main_advisor_id: main_advisor_id,
            co_advisor_id: co_advisor_id || null
        };
        
        // document_type_id = 1 คือ Form 1, status_id = 1 คือ 'รอตรวจ'
        const submissionQuery = `
            INSERT INTO document_submissions (student_user_id, document_type_id, status_id, student_comment, form_details)
            VALUES ($1, 1, 1, $2, $3)
            RETURNING id;
        `;
        const submissionResult = await client.query(submissionQuery, [
            student_user_id, 
            student_comment, 
            JSON.stringify(formDetails) 
        ]);
        const newSubmissionId = submissionResult.rows[0].id;

        // บันทึก Log การดำเนินการ
        const logQuery = `
            INSERT INTO submission_logs (submission_id, actor_user_id, action)
            VALUES ($1, $2, 'นักศึกษายื่นเอกสาร');
        `;
        await client.query(logQuery, [newSubmissionId, student_user_id]);

        await client.query('COMMIT');
        res.status(201).json({ message: 'ยื่นฟอร์มสำเร็จ!', submissionId: newSubmissionId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error submitting Form 1:', error);
        res.status(500).json({ message: 'Server Error' });
    } finally {
        client.release();
    }
});

// --- API สำหรับดึงข้อมูลสำหรับหน้าฟอร์ม 2 ---
app.get('/api/forms/form2-data/:userId', authenticateToken,  async (req, res) => {
    const { userId } = req.params;
    try {
        // 1. ดึงข้อมูลนักศึกษา (ส่วนนี้ถูกต้องแล้ว)
        const studentQuery = `
            SELECT 
                u.id, u.email, sp.student_id,
                u.prefix_th, u.first_name_th, u.last_name_th,
                sp.degree, sp.plan, sp.faculty, sp.phone,
                p.name AS program_name,
                d.name AS department_name,
                sp.main_advisor_id,
                sp.co_advisor1_id
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE u.id = $1;
        `;
        const studentResult = await pool.query(studentQuery, [userId]);
        if (studentResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลนักศึกษา' });
        }
        const studentData = studentResult.rows[0];

        // 2. ดึงชื่อเต็มของอาจารย์ที่ปรึกษา (ส่วนนี้ถูกต้องแล้ว)
        const advisorIds = [studentData.main_advisor_id, studentData.co_advisor1_id].filter(Boolean);
        let assignedAdvisors = [];
        if (advisorIds.length > 0) {
            // โค้ดที่แก้ไขแล้ว (แก้ทั้ง 2 ปัญหา)
            const assignedAdvisorsQuery = `
                SELECT ap.advisor_id, u.prefix_th, u.first_name_th, u.last_name_th
                FROM advisor_profiles ap
                JOIN users u ON ap.user_id = u.id
                WHERE ap.advisor_id = ANY($1::text[]);
            `;
            const assignedAdvisorsResult = await pool.query(assignedAdvisorsQuery, [advisorIds]);
            assignedAdvisors = assignedAdvisorsResult.rows;
        }
        const mainAdvisor = assignedAdvisors.find(a => a.advisor_id === studentData.main_advisor_id);
        const coAdvisor1 = assignedAdvisors.find(a => a.advisor_id === studentData.co_advisor1_id);
        const mainAdvisorName = mainAdvisor ? `${mainAdvisor.prefix_th}${mainAdvisor.first_name_th} ${mainAdvisor.last_name_th}`.trim() : 'ไม่มีข้อมูล';
        const coAdvisor1Name = coAdvisor1 ? `${coAdvisor1.prefix_th}${coAdvisor1.first_name_th} ${coAdvisor1.last_name_th}`.trim() : 'ไม่มีข้อมูล';

        // 3. ดึงรายชื่ออาจารย์ทั้งหมด
        const allAdvisorsQuery = `
            SELECT ap.advisor_id, ap.advisor_type, ap.roles, u.prefix_th, u.first_name_th, u.last_name_th
            FROM advisor_profiles ap
            JOIN users u ON ap.user_id = u.id;
        `;
        const allAdvisorsResult = await pool.query(allAdvisorsQuery);
        const allAdvisors = allAdvisorsResult.rows;

        // 4. กรองรายชื่ออาจารย์สำหรับแต่ละตำแหน่ง
        const usedAdvisorIds = [studentData.main_advisor_id, studentData.co_advisor1_id].filter(Boolean);
        const internalAdvisors = allAdvisors.filter(a => a.advisor_type !== 'อาจารย์บัณฑิตพิเศษภายนอก');
        const externalAdvisors = allAdvisors.filter(a => a.advisor_type === 'อาจารย์บัณฑิตพิเศษภายนอก');

        // ✅✅✅ แก้ไข Logic: กลับมาใช้การกรองตาม 'roles' ที่อัปเดตแล้ว ✅✅✅
        const responseData = {
            studentInfo: {
                fullname: `${studentData.prefix_th} ${studentData.first_name_th} ${studentData.last_name_th}`.trim(),
                ...studentData
            },
            advisorLists: {
                mainAdvisorName,
                coAdvisor1Name,
                potentialChairs: internalAdvisors.filter(a => a.roles?.includes("ประธานสอบ") && !usedAdvisorIds.includes(a.advisor_id)),
                potentialCoAdvisors2: internalAdvisors.filter(a => a.roles?.includes("ที่ปรึกษาร่วม") && !usedAdvisorIds.includes(a.advisor_id)),
                internalMembers: internalAdvisors.filter(a => !usedAdvisorIds.includes(a.advisor_id)),
                externalMembers: externalAdvisors,
            }
        };

        res.json(responseData);

    } catch (error) {
        console.error('Error fetching data for Form 2:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดใน Server' });
    }
});

// --- API สำหรับบันทึกข้อมูลจากฟอร์ม 2 ---
app.post('/api/submissions/form2',authenticateToken, async (req, res) => {
    const submissionData = req.body;

    try {
        // 1. จัดการไฟล์ที่ส่งมาเป็น Data URL
        const savedFiles = [];
        for (const file of submissionData.files) {
            // แยกส่วน base64 ออกจาก metadata
            const matches = file.url.match(/^data:(.+);base64,(.+)$/);
            if (!matches || matches.length !== 3) {
                throw new Error('Invalid Data URL format');
            }
            const fileBuffer = Buffer.from(matches[2], 'base64');
            
            // สร้างชื่อไฟล์ใหม่ที่ไม่ซ้ำกัน
            const fileExtension = path.extname(file.name);
            const uniqueFileName = `submission_${Date.now()}_${Math.random().toString(36).substring(2, 9)}${fileExtension}`;
            const filePath = path.join(__dirname, 'uploads', uniqueFileName);

            // บันทึกไฟล์ลงในโฟลเดอร์ uploads
            fs.writeFileSync(filePath, fileBuffer);

            // เก็บ path ที่จะบันทึกลง DB
            savedFiles.push({
                type: file.type,
                name: file.name,
                path: `/uploads/${uniqueFileName}` // path ที่จะใช้ใน client
            });
        }

        // 2. เตรียมข้อมูล JSON สำหรับคอลัมน์ form_details
        const formDetails = {
            thesis_title_th: submissionData.thesis_title_th,
            thesis_title_en: submissionData.thesis_title_en,
            committee: submissionData.committee,
            files: savedFiles, // ใช้ข้อมูลไฟล์ที่บันทึกแล้ว
            details: submissionData.details
        };

        // 3. บันทึกข้อมูลลงในตาราง document_submissions
        const insertQuery = `
            INSERT INTO document_submissions (
                student_user_id, 
                document_type_id, 
                status_id, 
                submission_date, 
                student_comment, 
                form_details
            ) VALUES ($1, $2, $3, NOW(), $4, $5)
            RETURNING *;
        `;
        const values = [
            submissionData.student_user_id,
            2, // document_type_id ของฟอร์ม 2 คือ 2
            1, // status_id เริ่มต้น 'รอตรวจ' คือ 1
            submissionData.student_comment,
            JSON.stringify(formDetails)
        ];

        const result = await pool.query(insertQuery, values);
        
        res.status(201).json({ message: 'ยื่นฟอร์ม 2 สำเร็จ!', data: result.rows[0] });

    } catch (error) {
        console.error('Error submitting Form 2:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล' });
    }
});

// --- API สำหรับดึงข้อมูลที่จำเป็นสำหรับ Form 3 ---
app.get('/api/forms/form3-data/:userId', authenticateToken, async (req, res) => {
    const { userId } = req.params;
    try {
        // 1. ดึงข้อมูลพื้นฐานของนักศึกษา
        const studentQuery = `
            SELECT 
                u.id, u.prefix_th, u.first_name_th, u.last_name_th, sp.student_id,
                sp.degree, p.name as program_name, d.name as department_name,
                sp.main_advisor_id, sp.co_advisor1_id
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE u.id = $1;
        `;
        const studentResult = await pool.query(studentQuery, [userId]);
        if (studentResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลนักศึกษา' });
        }
        const studentData = studentResult.rows[0];

        // 2. ค้นหา "ฟอร์ม 2" ล่าสุดที่อนุมัติแล้ว
        // ✅ แก้ไข: ลบ action_date ที่ไม่มีอยู่จริงออกจาก Query
        const form2Query = `
            SELECT form_details, submission_date 
            FROM document_submissions
            WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 -- status_id = 3 คือ 'อนุมัติแล้ว'
            ORDER BY submission_date DESC
            LIMIT 1;
        `;
        const form2Result = await pool.query(form2Query, [userId]);
        
        const isForm2Approved = form2Result.rows.length > 0;
        const approvedForm2Data = isForm2Approved ? form2Result.rows[0] : {};
        const form2Details = approvedForm2Data.form_details || {};

        // 3. ดึงรายชื่ออาจารย์ทั้งหมดเพื่อค้นหาชื่อ
        const advisorsResult = await pool.query('SELECT ap.advisor_id, u.prefix_th, u.first_name_th, u.last_name_th FROM advisor_profiles ap JOIN users u ON ap.user_id = u.id');
        const allAdvisors = advisorsResult.rows;

        const findAdvisorName = (id) => {
            if (!id) return 'ไม่มีข้อมูล';
            const advisor = allAdvisors.find(a => a.advisor_id === id);
            return advisor ? `${advisor.prefix_th}${advisor.first_name_th} ${advisor.last_name_th}`.trim() : 'ไม่พบข้อมูล';
        };

        // 4. ประกอบร่าง JSON เพื่อส่งกลับ
        const responseData = {
            isForm2Approved: isForm2Approved,
            fullname: `${studentData.prefix_th} ${studentData.first_name_th} ${studentData.last_name_th}`.trim(),
            student_id: studentData.student_id,
            degree: studentData.degree,
            programName: studentData.program_name,
            departmentName: studentData.department_name,
            // ✅ แก้ไข: ใช้ submission_date แทน (เนื่องจากไม่มี action_date)
            proposal_approval_date: approvedForm2Data.submission_date, 
            thesis_title_th: form2Details.thesis_title_th || "ยังไม่มีข้อมูล (รอฟอร์ม 2 อนุมัติ)",
            thesis_title_en: form2Details.thesis_title_en || "ยังไม่มีข้อมูล (รอฟอร์ม 2 อนุมัติ)",
            mainAdvisorName: findAdvisorName(studentData.main_advisor_id),
            coAdvisor1Name: findAdvisorName(studentData.co_advisor1_id),
            coAdvisor2Name: findAdvisorName(form2Details.committee?.co_advisor2_id),
            programChairId: form2Details.committee?.chair_id,
            programChairName: findAdvisorName(form2Details.committee?.chair_id),
        };
        
        res.json(responseData);

    } catch (error) {
        console.error('Error fetching data for Form 3:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดใน Server' });
    }
});

// --- API สำหรับบันทึกข้อมูลจากฟอร์ม 3 ---
app.post('/api/submissions/form3', authenticateToken, async (req, res) => {
    const { student_user_id, files, student_comment, approvers } = req.body;

    try {
        // 1. จัดการไฟล์ที่ส่งมาเป็น Data URL (เหมือนฟอร์ม 2)
        const savedFiles = [];
        for (const file of files) {
            const matches = file.url.match(/^data:(.+);base64,(.+)$/);
            if (!matches || matches.length !== 3) throw new Error('Invalid Data URL format');
            
            const fileBuffer = Buffer.from(matches[2], 'base64');
            const fileExtension = path.extname(file.name);
            const uniqueFileName = `submission_${Date.now()}_${Math.random().toString(36).substring(2, 9)}${fileExtension}`;
            const filePath = path.join(__dirname, 'uploads', uniqueFileName);

            fs.writeFileSync(filePath, fileBuffer);
            savedFiles.push({ type: file.type, name: file.name, path: `/uploads/${uniqueFileName}` });
        }

        // 2. เตรียมข้อมูล JSON สำหรับคอลัมน์ form_details
        const formDetails = {
            files: savedFiles,
            approvers: approvers // เก็บ ID ของผู้ที่จะต้องอนุมัติ (ประธานหลักสูตร)
        };

        // 3. บันทึกข้อมูลลงในตาราง document_submissions
        const insertQuery = `
            INSERT INTO document_submissions 
                (student_user_id, document_type_id, status_id, submission_date, student_comment, form_details)
            VALUES ($1, 3, 1, NOW(), $2, $3) -- document_type_id = 3 คือ ฟอร์ม 3
            RETURNING *;
        `;
        const values = [student_user_id, student_comment, JSON.stringify(formDetails)];
        const result = await pool.query(insertQuery, values);
        
        res.status(201).json({ message: 'ยื่นฟอร์ม 3 สำเร็จ!', data: result.rows[0] });

    } catch (error) {
        console.error('Error submitting Form 3:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล' });
    }
});

// --- API สำหรับการยื่นผลสอบภาษาอังกฤษ (Form 7) ---
app.post('/api/submissions/exam-result', authenticateToken, async (req, res) => {
    const { 
        student_user_id, 
        document_type_id,
        student_comment, 
        form_details, // นี่คืออ็อบเจกต์ที่ประกอบด้วย {exam_type, exam_date, reading_score, ..., files}
    } = req.body;

    if (!student_user_id || !document_type_id || !form_details || !form_details.files) {
        return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const savedFilePaths = [];
        for (const file of form_details.files) {
            // ... (โค้ดสำหรับแปลงและบันทึกไฟล์ Base64)
            const base64Data = file.url.replace(/^data:.+;base64,/, "");
            const fileBuffer = Buffer.from(base64Data, 'base64');
            
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            const extension = path.extname(file.name);
            const fileName = `exam_${student_user_id}_${uniqueSuffix}${extension}`;
            const filePath = path.join(__dirname, 'uploads', fileName);

            fs.writeFileSync(filePath, fileBuffer);

            savedFilePaths.push({ name: file.name, path: `/uploads/${fileName}` });
        }
        
        // ✅✅✅ โค้ดที่แก้ไข: ใช้ Spread Operator เพื่อดึงฟิลด์คะแนนทั้งหมด ✅✅✅
        const finalFormDetails = {
            ...form_details, // ดึงทุกอย่างมาจาก Frontend (รวมถึง exam_type, exam_date และ คะแนนย่อยทั้งหมด)
            files: savedFilePaths // Overwrite เฉพาะไฟล์ที่ถูกประมวลผลแล้ว
        };

        // 💡 DEBUG: ตรวจสอบว่าคะแนนเข้าก่อนบันทึก
        console.log("FINAL FORM DETAILS TO SAVE:", finalFormDetails);

        const submissionQuery = `
            INSERT INTO document_submissions (student_user_id, document_type_id, status_id, student_comment, form_details)
            VALUES ($1, $2, 1, $3, $4)
            RETURNING id;
        `;
        const result = await client.query(submissionQuery, [ student_user_id, document_type_id, student_comment, finalFormDetails ]);
        const newSubmissionId = result.rows[0].id;
        
        await client.query(
          `INSERT INTO submission_logs (submission_id, actor_user_id, action) VALUES ($1, $2, 'นักศึกษายื่นเอกสาร')`,
          [newSubmissionId, student_user_id]
        );

        await client.query('COMMIT');
        res.status(201).json({ message: 'ยื่นผลสอบสำเร็จ!', submissionId: newSubmissionId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error submitting exam result:', error);
        res.status(500).json({ message: 'Server Error' });
    } finally {
        client.release();
    }
});

// --- API สำหรับการยื่นผลสอบวัดคุณสมบัติ (QE) ---
app.post('/api/submissions/qe-result', authenticateToken, async (req, res) => {
    const { 
        student_user_id, 
        student_comment, 
        form_details 
    } = req.body;

    // ✅ แก้ไข: ตรวจสอบคีย์ 'files' และความยาวของ Array
    if (
        !student_user_id || 
        !form_details || 
        !form_details.result || 
        !form_details.files || 
        form_details.files.length === 0
    ) {
        return res.status(400).json({ message: 'ข้อมูลฟอร์มไม่ครบถ้วนหรือไม่ถูกต้อง (Bad Request)' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // ✅ แก้ไข: ดึงไฟล์ตัวแรกออกจาก Array files
        const file = form_details.files[0]; 
        const base64Data = file.url.replace(/^data:.+;base64,/, "");
        const fileBuffer = Buffer.from(base64Data, 'base64');
        
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const extension = path.extname(file.name);
        const fileName = `qe_${student_user_id}_${uniqueSuffix}${extension}`;
        const filePath = path.join(__dirname, 'uploads', fileName);

        fs.writeFileSync(filePath, fileBuffer);
        const savedFilePath = { name: file.name, path: `/uploads/${fileName}` };

        // ✅ ปรับโครงสร้าง finalFormDetails ให้ชัดเจน
        const finalFormDetails = {
            result: form_details.result,
            files: [savedFilePath] // ข้อมูลที่บันทึก
        };

        const submissionQuery = `
            INSERT INTO document_submissions (student_user_id, document_type_id, status_id, student_comment, form_details)
            VALUES ($1, 9, 1, $2, $3) RETURNING id;
        `;
        const result = await client.query(submissionQuery, [student_user_id, student_comment, finalFormDetails]);
        const newSubmissionId = result.rows[0].id;
        
        await client.query(
          `INSERT INTO submission_logs (submission_id, actor_user_id, action) VALUES ($1, $2, 'นักศึกษายื่นเอกสาร')`,
          [newSubmissionId, student_user_id]
        );

        await client.query('COMMIT');
        res.status(201).json({ message: 'ยื่นผลสอบวัดคุณสมบัติ (QE) สำเร็จ!', submissionId: newSubmissionId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error submitting QE result:', error);
        // สามารถส่งข้อความที่ละเอียดขึ้นได้ แต่ 500 Server Error ก็ใช้ได้
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการประมวลผลเซิร์ฟเวอร์' });
    } finally {
        client.release();
    }
});

// --- API สำหรับการยื่น Form 4 ---
app.post('/api/submissions/form4', authenticateToken, async (req, res, next) => {
    try {
        const { student_user_id, student_comment, form_details } = req.body;

        if (!student_user_id || !form_details) {
            return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });
        }

        // document_type_id = 4 คือ Form 4, status_id = 1 คือ 'รอตรวจ'
        const submissionQuery = `
            INSERT INTO document_submissions (student_user_id, document_type_id, status_id, student_comment, form_details)
            VALUES ($1, 4, 1, $2, $3)
            RETURNING id;
        `;
        
        const submissionResult = await pool.query(submissionQuery, [student_user_id, student_comment, form_details]);
        const newSubmissionId = submissionResult.rows[0].id;

        // บันทึก Log
        await pool.query(
            `INSERT INTO submission_logs (submission_id, actor_user_id, action) VALUES ($1, $2, 'นักศึกษายื่นเอกสาร')`,
            [newSubmissionId, student_user_id]
        );

        res.status(201).json({ message: 'ยื่นฟอร์ม 4 สำเร็จ!', submissionId: newSubmissionId });

    } catch (error) {
        next(error);
    }
});

app.get('/api/forms/form4-data/:userId', authenticateToken, async (req, res, next) => {
    try {
        const { userId } = req.params;

        const studentQuery = `
            SELECT 
                u.id, u.prefix_th, u.first_name_th, u.last_name_th,
                sp.student_id, sp.degree, sp.plan, sp.faculty,
                sp.program_id, sp.department_id, sp.main_advisor_id,
                p.name as program_name, d.name as department_name,
                (SELECT form_details->>'thesis_title_th' FROM document_submissions 
                 WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 
                 ORDER BY submission_date DESC LIMIT 1) as thesis_title_th,
                (SELECT form_details->>'thesis_title_en' FROM document_submissions 
                 WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 
                 ORDER BY submission_date DESC LIMIT 1) as thesis_title_en,
                (SELECT action_date FROM document_submissions 
                 WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 
                 ORDER BY submission_date DESC LIMIT 1) as proposal_approval_date
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE u.id = $1;
        `;
        const studentResult = await pool.query(studentQuery, [userId]);
        if (studentResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลนักศึกษา' });
        }
        
        const studentData = studentResult.rows[0];
        studentData.fullname = `${studentData.prefix_th || ''} ${studentData.first_name_th || ''} ${studentData.last_name_th || ''}`.trim();


        // 2. ดึงรายชื่ออาจารย์ทั้งหมด
        const advisorsRes = await pool.query('SELECT u.id, ap.advisor_id, u.prefix_th, u.first_name_th, u.last_name_th, u.email as contact_email FROM users u JOIN advisor_profiles ap ON u.id = ap.user_id');

        // 3. ส่งข้อมูลทั้งหมดกลับไป
        res.json({
            studentInfo: studentData,
            advisors: advisorsRes.rows
        });

    } catch (error) {
        next(error); // ส่ง Error ไปให้ Global Handler
    }
});

// --- API สำหรับดึงข้อมูลที่จำเป็นสำหรับ Form 5 ---
app.get('/api/forms/form5-data/:userId', authenticateToken, async (req, res, next) => {
    try {
        const { userId } = req.params;
        
        const studentQuery = `
            SELECT 
                u.id, u.prefix_th, u.first_name_th, u.last_name_th, u.email,
                sp.student_id, sp.degree, sp.phone,
                p.name as program_name,
                (SELECT form_details->>'thesis_title_th' FROM document_submissions 
                 WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 
                 ORDER BY submission_date DESC LIMIT 1) as thesis_title_th,
                (SELECT form_details->>'thesis_title_en' FROM document_submissions 
                 WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 
                 ORDER BY submission_date DESC LIMIT 1) as thesis_title_en,
                (SELECT action_date FROM document_submissions 
                 WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 
                 ORDER BY submission_date DESC LIMIT 1) as proposal_approval_date
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            WHERE u.id = $1;
        `;
        const studentResult = await pool.query(studentQuery, [userId]);
        if (studentResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลนักศึกษา' });
        }
        
        const studentData = studentResult.rows[0];
        studentData.fullname = `${studentData.prefix_th || ''} ${studentData.first_name_th || ''} ${studentData.last_name_th || ''}`.trim();

        res.json({ studentInfo: studentData });
    } catch (error) {
        next(error);
    }
});

// --- API สำหรับการยื่น Form 5 ---
app.post('/api/submissions/form5', authenticateToken, async (req, res, next) => {
    try {
        const { student_user_id, student_comment, form_details } = req.body;
        if (!student_user_id || !form_details) {
            return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });
        }

        // document_type_id = 5 คือ Form 5
        const submissionQuery = `
            INSERT INTO document_submissions (student_user_id, document_type_id, status_id, student_comment, form_details)
            VALUES ($1, 5, 1, $2, $3) RETURNING id;
        `;
        const result = await pool.query(submissionQuery, [student_user_id, student_comment, form_details]);
        const newSubmissionId = result.rows[0].id;

        await pool.query(
            `INSERT INTO submission_logs (submission_id, actor_user_id, action) VALUES ($1, $2, 'นักศึกษายื่นเอกสาร')`,
            [newSubmissionId, student_user_id]
        );

        res.status(201).json({ message: 'ยื่นฟอร์ม 5 สำเร็จ!', submissionId: newSubmissionId });
    } catch (error) {
        next(error);
    }
});

// --- API สำหรับดึงข้อมูลที่จำเป็นสำหรับ Form 6 (แก้ไขแล้ว) ---
app.get('/api/forms/form6-data/:userId', authenticateToken, async (req, res, next) => {
    try {
        const { userId } = req.params;
        
        // 1. ดึงข้อมูลนักศึกษา (ส่วนนี้เหมือนเดิม)
        const studentQuery = `
            SELECT 
                u.id, u.prefix_th, u.first_name_th, u.last_name_th, u.email,
                sp.*, 
                p.name as program_name, d.name as department_name,
                (SELECT form_details FROM document_submissions 
                 WHERE student_user_id = $1 AND document_type_id = 2 AND status_id = 3 
                 ORDER BY submission_date DESC LIMIT 1) as form2_details
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE u.id = $1;
        `;
        const studentResult = await pool.query(studentQuery, [userId]);
        if (studentResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลนักศึกษา' });
        }
        
        const studentData = studentResult.rows[0];
        studentData.fullname = `${studentData.prefix_th || ''} ${studentData.first_name_th || ''} ${studentData.last_name_th || ''}`.trim();
        studentData.committee_from_form2 = studentData.form2_details?.committee || {};
        delete studentData.form2_details;

        // ✅✅✅ 2. แก้ไข Query ให้ดึงคอลัมน์ roles มาด้วย ✅✅✅
        const advisorsRes = await pool.query(`
            SELECT 
                u.id, 
                ap.advisor_id, 
                u.prefix_th, 
                u.first_name_th, 
                u.last_name_th, 
                ap.advisor_type,
                ap.roles -- <-- ดึงคอลัมน์ roles มาจาก advisor_profiles
            FROM users u 
            JOIN advisor_profiles ap ON u.id = ap.user_id
        `);
        const allAdvisors = advisorsRes.rows;

        const usedAdvisorIds = [
            studentData.main_advisor_id, 
            studentData.co_advisor1_id
        ].filter(Boolean);

        // ✅✅✅ 3. แก้ไข Logic การกรองข้อมูลด้วย JavaScript ✅✅✅
        const advisorLists = {
            // กรองหาเฉพาะอาจารย์ที่มี role 'ประธานสอบ' และไม่ใช่ อ.ที่ปรึกษาของนักศึกษาอยู่แล้ว
            potentialChairs: allAdvisors.filter(adv => 
                adv.roles?.includes('ประธานสอบ') && !usedAdvisorIds.includes(adv.advisor_id)
            ),
             // กรองหาเฉพาะอาจารย์ที่มี role 'ที่ปรึกษาร่วม' และไม่ใช่ อ.ที่ปรึกษาของนักศึกษาอยู่แล้ว
            potentialCoAdvisors2: allAdvisors.filter(adv => 
                adv.roles?.includes('ที่ปรึกษาร่วม') && !usedAdvisorIds.includes(adv.advisor_id)
            ),
            internalMembers: allAdvisors, // ส่งอาจารย์ทั้งหมดไปสำหรับช่องอื่นๆ
            externalMembers: allAdvisors.filter(adv => adv.advisor_type?.includes('ภายนอก')),
        };

        res.json({ studentInfo: studentData, advisorLists });
    } catch (error) {
        next(error);
    }
});


// --- API สำหรับการยื่น Form 6 (แก้ไขแล้ว) ---
app.post('/api/submissions/form6', authenticateToken, async (req, res, next) => {
    const { student_user_id, student_comment, form_details } = req.body;

    if (!student_user_id || !form_details || !form_details.files) {
        return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน โดยเฉพาะข้อมูลไฟล์' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. สร้าง object เพื่อเก็บข้อมูลไฟล์ที่จะบันทึกลง DB (ชื่อ + path)
        const savedFiles = {};
        const filesToProcess = form_details.files; // ดึง object ไฟล์ออกมา

        // 2. วนลูปเพื่อจัดการไฟล์แต่ละตัว
        for (const fileKey in filesToProcess) {
            const fileData = filesToProcess[fileKey]; // { name: '...', url: 'data:...' }

            // 3. แปลง Base64 Data URL เป็น Buffer
            const base64Data = fileData.url.replace(/^data:.+;base64,/, "");
            const fileBuffer = Buffer.from(base64Data, 'base64');
            
            // 4. สร้างชื่อไฟล์ใหม่ที่ไม่ซ้ำกัน
            const originalExtension = path.extname(fileData.name);
            const uniqueFileName = `form6_${student_user_id}_${fileKey}_${Date.now()}${originalExtension}`;
            const filePath = path.join(__dirname, 'uploads', uniqueFileName);

            // 5. บันทึกไฟล์ลงในโฟลเดอร์ uploads
            fs.writeFileSync(filePath, fileBuffer);

            // 6. เก็บข้อมูล path สำหรับบันทึกลง DB
            savedFiles[fileKey] = {
                name: fileData.name,
                path: `/uploads/${uniqueFileName}` // path ที่จะใช้ใน client
            };
        }

        // 7. สร้าง form_details object ตัวสุดท้ายที่จะบันทึกลง DB
        const finalFormDetails = {
            ...form_details,
            files: savedFiles // แทนที่ object ไฟล์เดิมด้วย object ที่มี path
        };

        // 8. บันทึกข้อมูลทั้งหมดลงในตาราง document_submissions
        const submissionQuery = `
            INSERT INTO document_submissions (student_user_id, document_type_id, status_id, student_comment, form_details)
            VALUES ($1, 6, 1, $2, $3) RETURNING id;
        `;
        const result = await client.query(submissionQuery, [student_user_id, student_comment, finalFormDetails]);
        const newSubmissionId = result.rows[0].id;

        // 9. บันทึก Log
        await client.query(
            `INSERT INTO submission_logs (submission_id, actor_user_id, action) VALUES ($1, $2, 'นักศึกษายื่นเอกสาร')`,
            [newSubmissionId, student_user_id]
        );

        await client.query('COMMIT');
        res.status(201).json({ message: 'ยื่นฟอร์ม 6 สำเร็จ!', submissionId: newSubmissionId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Error submitting Form 6:", error);
        next(error); // ส่งไปให้ error handler กลาง (ถ้ามี) หรือจะ res.status(500) ก็ได้
    } finally {
        client.release();
    }
});

app.get('/api/advisors/:advisorId/roles', authenticateToken, async (req, res, next) => {
    const { advisorId } = req.params;

    try {
        // 1. ค้นหา User ID ของอาจารย์จาก Advisor ID (เหมือนเดิม)
        const advisorUserRes = await pool.query('SELECT user_id FROM advisor_profiles WHERE advisor_id = $1', [advisorId]);
        if (advisorUserRes.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบข้อมูลอาจารย์' });
        }
        // const advisorUserId = advisorUserRes.rows[0].user_id; // ไม่ได้ใช้ใน Query นี้ แต่เก็บไว้ดีแล้ว

         const rolesQuery = `
            -- ส่วนที่ 1: ดึงบทบาท "ที่ปรึกษา"
            SELECT
                u.id as student_user_id, sp.student_id,
                CONCAT(u.prefix_th, u.first_name_th, ' ', u.last_name_th) as student_name,
                p.name as program_name, ss.status_name as student_status,
                CASE
                    WHEN sp.main_advisor_id = $1 THEN 'ที่ปรึกษาหลัก'
                    WHEN sp.co_advisor1_id = $1 THEN 'ที่ปรึกษาร่วม คนที่ 1'
                    WHEN sp.co_advisor2_id = $1 THEN 'ที่ปรึกษาร่วม คนที่ 2'
                END as role,
                'N/A' as document_title,
                NULL::TEXT as submission_id,
                u.updated_at as relevant_date
            FROM student_profiles sp
            JOIN users u ON sp.user_id = u.id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN student_statuses ss ON sp.status_id = ss.id
            WHERE sp.main_advisor_id = $1 OR sp.co_advisor1_id = $1 OR sp.co_advisor2_id = $1

            UNION ALL

            -- ส่วนที่ 2: ดึงบทบาท "กรรมการสอบ"
            SELECT
                ds.student_user_id, sp.student_id,
                CONCAT(u.prefix_th, u.first_name_th, ' ', u.last_name_th) as student_name,
                p.name as program_name, ss.status_name as student_status,
                CASE
                    WHEN (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'chair_id') = $1 THEN 'ประธานสอบ'
                    WHEN (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'member5_id') = $1 THEN 'กรรมการสอบ'
                    WHEN (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'reserve_internal_id') = $1 THEN 'อาจารย์สำรองภายใน'
                    WHEN (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'reserve_external_id') = $1 THEN 'อาจารย์สำรองภายนอก'
                END as role,
                dt.type_name as document_title,
                ds.id::TEXT as submission_id,
                ds.action_date as relevant_date
            FROM document_submissions ds
            JOIN users u ON ds.student_user_id = u.id
            JOIN student_profiles sp ON u.id = sp.user_id
            JOIN document_types dt ON ds.document_type_id = dt.id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN student_statuses ss ON sp.status_id = ss.id
            WHERE
                ds.status_id = 3 AND
                (ds.document_type_id = 2 OR ds.document_type_id = 6) AND
                (
                    (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'chair_id') = $1 OR
                    (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'member5_id') = $1 OR
                    (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'reserve_internal_id') = $1 OR
                    (COALESCE(ds.form_details, '{}')::jsonb -> 'committee' ->> 'reserve_external_id') = $1
                )
            ORDER BY relevant_date DESC;
        `;

        // 3. เรียกใช้งาน Query ด้วย .trim()
        const result = await pool.query(rolesQuery.trim(), [advisorId]); // <<< ใช้ .trim() ตรงนี้

        res.json(result.rows);

    } catch (error) {
        console.error(`[CRITICAL ERROR] Error fetching all roles for advisor ${advisorId}:`, error);
        next(error);
    }
});

// --- API สำหรับดึงข้อมูลเอกสารเพื่อนำไปแก้ไข (สำหรับโหมด Edit) ---
app.get('/api/submissions/:submissionId/edit', authenticateToken, async (req, res, next) => {
    const { submissionId } = req.params;
    const studentUserId = req.user.userId;

    try {
        // 1. ดึงข้อมูล Submission หลัก และตรวจสอบว่าเป็นของนักศึกษาคนนี้จริง
        const submissionQuery = `
            SELECT id, student_user_id, status_id, student_comment, admin_comment, form_details
            FROM document_submissions
            WHERE id = $1 AND student_user_id = $2;
        `;
        const submissionResult = await pool.query(submissionQuery, [submissionId, studentUserId]);

        if (submissionResult.rows.length === 0) {
            return res.status(404).json({ message: 'ไม่พบเอกสาร หรือไม่มีสิทธิ์ในการแก้ไข' });
        }
        
        const submissionData = submissionResult.rows[0];

        // 2. ดึงข้อมูลโปรไฟล์ของนักศึกษา
        const studentQuery = `
            SELECT 
                u.id, u.email, u.prefix_th, u.first_name_th, u.last_name_th,
                sp.student_id, sp.degree, sp.faculty, sp.plan, sp.phone,
                p.name as program_name,
                d.name as department_name
            FROM users u
            JOIN student_profiles sp ON u.id = sp.user_id
            LEFT JOIN programs p ON sp.program_id = p.id
            LEFT JOIN departments d ON sp.department_id = d.id
            WHERE u.id = $1;
        `;
        const studentResult = await pool.query(studentQuery, [studentUserId]);
        const studentInfo = studentResult.rows[0];

        // 3. ดึงรายชื่ออาจารย์ทั้งหมดสำหรับ Dropdown
        const advisorsQuery = `
            SELECT u.id, ap.advisor_id, u.prefix_th, u.first_name_th, u.last_name_th
            FROM users u
            JOIN advisor_profiles ap ON u.id = ap.user_id
            WHERE u.role_id = 3 ORDER BY u.first_name_th;
        `;
        const advisorsResult = await pool.query(advisorsQuery);

        // 4. ส่งข้อมูลทั้งหมดกลับไป
        res.json({
            submission: submissionData,
            studentInfo: studentInfo,
            advisors: advisorsResult.rows
        });

    } catch (error) {
        console.error(`Error fetching submission for edit: ${submissionId}`, error);
        next(error);
    }
});

// --- API สำหรับนักศึกษา Re-submit เอกสารที่ถูกตีกลับ ---
app.put('/api/submissions/:submissionId/resubmit', authenticateToken, async (req, res, next) => {
    const NEXT_ADMIN_REVIEW_STATUS_ID = 1; // สมมติว่า ID 1 คือ 'รอตรวจ' หรือ 'รอเจ้าหน้าที่ตรวจสอบ'

    const { submissionId } = req.params;
    const student_user_id = req.user.userId;
    const { form_details, student_comment } = req.body;

    if (!form_details) {
        return res.status(400).json({ message: 'ข้อมูลฟอร์มไม่ครบถ้วนสำหรับการ Re-submit' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. ตรวจสอบสิทธิ์และความถูกต้องของเอกสาร
        const currentDocRes = await client.query('SELECT status_id FROM document_submissions WHERE id = $1 AND student_user_id = $2', [submissionId, student_user_id]);
        if (currentDocRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'ไม่พบเอกสารหรือไม่มีสิทธิ์ดำเนินการ' });
        }
        
        // 2. อัปเดตเอกสารด้วยข้อมูลใหม่ และเปลี่ยนสถานะกลับไปรอตรวจ
        await client.query(
            `UPDATE document_submissions SET 
                status_id = $1, 
                student_comment = $2, 
                admin_comment = NULL, -- ล้างคอมเมนต์ของแอดมินออก
                form_details = $3, 
                submission_date = NOW(), 
                action_date = NULL -- ล้าง action_date เพื่อเริ่ม Workflow ใหม่
             WHERE id = $4`,
            [NEXT_ADMIN_REVIEW_STATUS_ID, student_comment, JSON.stringify(form_details), submissionId]
        );
        
        // 3. (สำคัญ) ล้าง Tasks การอนุมัติเก่าที่ค้างอยู่ทั้งหมดของเอกสารนี้
        await client.query(`DELETE FROM approval_tasks WHERE submission_id = $1`, [submissionId]);

        // 4. สร้าง Log การ Re-submit
        await client.query(
            `INSERT INTO submission_logs (submission_id, actor_user_id, action, log_comment) 
             VALUES ($1, $2, $3, $4)`,
            [submissionId, student_user_id, 'นักศึกษาส่งเอกสารกลับมาแก้ไข', student_comment || 'ไม่มีความคิดเห็นเพิ่มเติม']
        );

        // (ถ้ามี Workflow) คุณอาจจะต้องสร้าง approval_task ใหม่สำหรับ Admin ที่นี่
        // แต่ถ้าสถานะ "รอตรวจ" ถูกดึงไปแสดงในหน้า dashboard ของ Admin อยู่แล้ว ก็ไม่จำเป็น

        await client.query('COMMIT');
        res.status(200).json({ message: 'ส่งเอกสารกลับมาตรวจสอบใหม่สำเร็จ!', submissionId });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error on Re-submit:', error);
        next(error);
    } finally {
        client.release();
    }
});

const form2UploadFields = [
    { name: 'ไฟล์หัวข้อและเค้าโครงวิทยานิพนธ์ (ไทย)' },
    { name: 'ไฟล์หัวข้อและเค้าโครงวิทยานิพนธ์ (อังกฤษ)' },
    { name: 'ไฟล์หน้าปกของหัวข้อและเค้าโครง (ไทย)' },
    { name: 'ไฟล์หน้าปกของหัวข้อและเค้าโครง (อังกฤษ)' },
    { name: 'ไฟล์สำเนาการลงทะเบียนภาคการศึกษาล่าสุด' }
];


// ** GET Document Details by ID (*** FINAL COMPLETE VERSION ***) **
app.get('/api/documents/:id', authenticateToken, async (req, res) => {
    const documentId = req.params.id;
    const loggedInUserId = req.user.userId;
    const userRole = req.user.role;

    try {
        // --- 1. Query ที่สมบูรณ์: ดึงข้อมูลทั้งหมดที่จำเป็น ---
        const query = `
            SELECT 
                ds.id AS document_id, 
                ds.document_type_id, 
                dt.type_name, 
                ds.student_user_id,
                ds.student_comment,
                ds.admin_comment,
                ds.form_details,
                sp.main_advisor_id, 
                sp.co_advisor1_id,
                sp.co_advisor2_id
            FROM document_submissions ds
            JOIN document_types dt ON ds.document_type_id = dt.id
            JOIN users u ON ds.student_user_id = u.id
            LEFT JOIN student_profiles sp ON u.id = sp.user_id
            WHERE ds.id = $1
        `;
        const result = await pool.query(query, [documentId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Document not found.' });
        }
        const document = result.rows[0];
        
        // --- 2. การตรวจสอบสิทธิ์ (Authorization) ที่สมบูรณ์ ---
        const isOwner = document.student_user_id === loggedInUserId;
        const isAdmin = userRole === 'admin';
        
        if (!isOwner && !isAdmin) {
            return res.status(403).json({ message: 'Access Denied. You do not have permission to view this document.' });
        }
        
        // --- 3. "ตัวแปลงข้อมูล" (Data Transformer) ที่สมบูรณ์ ---
        const formDetails = document.form_details || {};
        
        let responseData = {
            id: document.document_id,
            document_type_id: document.document_type_id,
            type_name: document.type_name,
            student_comment: document.student_comment || '',
            admin_comment: document.admin_comment || '',
            files: formDetails.files || [],
            form_details: formDetails,
            main_advisor_id: document.main_advisor_id, 
            co_advisor1_id: document.co_advisor1_id,
            co_advisor2_id: document.co_advisor2_id 
        };

        switch (document.document_type_id) {
            case 1: // ฟอร์ม 1: ขอที่ปรึกษา
                responseData.description = `เสนอชื่ออาจารย์ที่ปรึกษาหลัก: ${formDetails.main_advisor_id || 'N/A'}`;
                responseData.main_advisor_id = formDetails.main_advisor_id || '';
                responseData.co_advisor_id = formDetails.co_advisor_id || '';
                break;

            case 2: // ฟอร์ม 2
                const committee = formDetails.committee || {};
                responseData.thesis_title_th = formDetails.thesis_title_th || '';
                responseData.thesis_title_en = formDetails.thesis_title_en || '';
                responseData.co_advisor2_id = committee.co_advisor2_id || '';
                responseData.chair_id = committee.chair_id || '';
                responseData.member5_id = committee.member5_id || '';
                responseData.reserve_internal_id = committee.reserve_internal_id || '';
                responseData.reserve_external_id = committee.reserve_external_id || '';
                break;

            case 4: // ฟอร์ม 4: ขอเชิญผู้ทรงคุณวุฒิ
                responseData.description = 'แบบขอหนังสือเชิญผู้ทรงคุณวุฒิตรวจและประเมิน...เพื่อการวิจัย';
                break;

                case 9: // ยื่นผลสอบวัดคุณสมบัติ
               responseData.exam_date = formDetails.exam_date || '';
               responseData.result = formDetails.result || '';
               break;

            default:
                responseData.description = formDetails.description || 'ไม่มีรายละเอียด';
                break;
        }

        res.json({ data: responseData });

    } catch (error) {
        console.error(`Error fetching document ${documentId}:`, error);
        res.status(500).json({ message: `Server Error: ${error.message}` });
    }
});

app.put('/api/documents/:id', authenticateToken, upload.any(), async (req, res) => {
    const documentId = req.params.id;
    const userId = req.user.userId;
    const userRole = req.user.role;
    const updatedData = req.body; 
    const newFiles = req.files; 
    const NEXT_ADMIN_REVIEW_STATUS_ID = 1; 
    const requiredFileTypesForForm6DB = Object.values(form6TypeMap);

    const form6TypeMap = {
        'thesisDraftFile': 'วิทยานิพนธ์ฉบับสมบูรณ์', 
        'abstractThFile': 'บทคัดย่อ (ภาษาไทย)', 
        'abstractEnFile': 'บทคัดย่อ (ภาษาอังกฤษ)', 
        'tocThFile': 'สารบัญฯ (ภาษาไทย)',
        'tocEnFile': 'สารบัญฯ (ภาษาอังกฤษ)',
        'publicationProofFile': 'หลักฐานการตอบรับการตีพิมพ์/นำเสนอผลงาน',
        'gradeCheckProofFile': 'หลักฐานการตรวจสอบผลการเรียน',
    };

    try {
        const currentDocResult = await pool.query(
            'SELECT student_user_id, form_details, document_type_id FROM document_submissions WHERE id = $1', 
            [documentId]
        );

        if (currentDocResult.rows.length === 0) {
            return res.status(404).json({ message: 'Document not found' });
        }
        
        const currentDoc = currentDocResult.rows[0];
        let newFormDetails = currentDoc.form_details || {};
        const oldFiles = Array.isArray(newFormDetails.files) ? newFormDetails.files : [];
        if (!newFormDetails.committee) newFormDetails.committee = {};
        if (!newFormDetails.evaluators) newFormDetails.evaluators = [];
        if (!newFormDetails.document_types) newFormDetails.document_types = [];

        // --- Authorization Check ---
        const studentId = currentDoc.student_user_id;
        if (studentId !== userId && userRole !== 'admin') {
            return res.status(403).json({ message: 'Forbidden.' });
        }

        // --- File Rebuilding Logic ---
        const finalFiles = []; 
        const newFilesMap = {};

        if (newFiles && newFiles.length > 0) {
            for (const uploadedFile of newFiles) {
                const fieldName = iconv.decode(Buffer.from(uploadedFile.fieldname, 'binary'), 'utf8');
                
                // ⭐ 2. [แก้ไข] กำหนดชื่อ Type ที่จะบันทึก: ใช้ชื่อไทยเต็มสำหรับ Form 6 
                let fileTypeToSave = fieldName;
                if (currentDoc.document_type_id === 6 && form6TypeMap[fieldName]) {
                    fileTypeToSave = form6TypeMap[fieldName];
                } else {
                    // สำหรับ Form 2 และฟอร์มอื่น ๆ (ที่ไม่ใช่ Form 6) ให้ใช้ fieldName เดิม (ซึ่งคือชื่อไทยเต็ม)
                    fileTypeToSave = fieldName;
                }
                
                const originalFilename = iconv.decode(Buffer.from(uploadedFile.originalname, 'binary'), 'utf8');
                const newFilePath = `uploads/${path.basename(uploadedFile.path)}`;
                
                // บันทึกเข้า Map โดยใช้ชื่อ Type ภาษาไทยเต็ม (fileTypeToSave)
                newFilesMap[fileTypeToSave] = { type: fileTypeToSave, name: originalFilename, path: newFilePath };
            }
        }
        
        // 3. [แก้ไข] กำหนดรายการไฟล์ที่จำเป็น (ชื่อ Type ที่อยู่ในฐานข้อมูล)
        const requiredFileTypesForForm2 = [
            'ไฟล์หัวข้อและเค้าโครงวิทยานิพนธ์ (ไทย)', 'ไฟล์หัวข้อและเค้าโครงวิทยานิพนธ์ (อังกฤษ)',
            'ไฟล์หน้าปกของหัวข้อและเค้าโครง (ไทย)', 'ไฟล์หน้าปกของหัวข้อและเค้าโครง (อังกฤษ)',
            'ไฟล์สำเนาการลงทะเบียนภาคการศึกษาล่าสุด'
        ];
        // ⭐ [ใหม่] ใช้ Object.values เพื่อดึงชื่อไทยเต็มจาก Map สำหรับ Form 6
        const requiredFileTypesDB = currentDoc.document_type_id === 2 
           ? requiredFileTypesForForm2 
           : (currentDoc.document_type_id === 6 
               ? requiredFileTypesForForm6DB
               : (currentDoc.document_type_id === 7 || currentDoc.document_type_id === 8
                   ? ['english_exam_file']           
                   : (currentDoc.document_type_id === 9 // <-- เพิ่มเงื่อนไขตรงนี้
                       ? ['qualifying_exam_file']      // <-- ให้มองหาไฟล์ชื่อนี้
                       : (currentDoc.document_type_id !== 4 ? ['document_file'] : [])))); 

        // สร้างลิสต์ไฟล์ใหม่ทั้งหมด
        for (const fileType of requiredFileTypesDB) { // วนลูปด้วยชื่อ Type ภาษาไทยเต็ม
            if (newFilesMap[fileType]) {
                // ถ้ามีการอัปโหลดไฟล์ใหม่ (newFilesMap ถูกสร้างด้วยชื่อไทยเต็ม)
                finalFiles.push(newFilesMap[fileType]);
            } else {
                // ค้นหาไฟล์เก่าด้วยชื่อไทยเต็ม
                const oldFile = oldFiles.find(f => f.type === fileType); 
                if (oldFile) {
                    finalFiles.push(oldFile);
                }
            }
        }
        newFormDetails.files = finalFiles; // เขียนทับด้วยลิสต์ไฟล์ที่สะอาดแล้ว

        // --- Text Data Update Logic ---
        // ... (ส่วนนี้ไม่มีการเปลี่ยนแปลง)
        switch (currentDoc.document_type_id) {
            case 1:
                newFormDetails.main_advisor_id = updatedData.main_advisor_id;
                newFormDetails.co_advisor_id = updatedData.co_advisor_id;
                break;
            case 2:
                newFormDetails.thesis_title_th = updatedData.thesis_title_th;
                newFormDetails.thesis_title_en = updatedData.thesis_title_en;
                newFormDetails.committee.chair_id = updatedData.chair_id;
                newFormDetails.committee.co_advisor2_id = updatedData.co_advisor2_id;
                newFormDetails.committee.member5_id = updatedData.member5_id;
                newFormDetails.committee.reserve_internal_id = updatedData.reserve_internal_id;
                newFormDetails.committee.reserve_external_id = updatedData.reserve_external_id;
                break;
            case 4:
                // ... (Form 4 logic)
                try {
                    const parsedEvaluators = JSON.parse(updatedData.evaluators);
                    const parsedDocTypes = JSON.parse(updatedData.document_types);

                    if (Array.isArray(parsedEvaluators)) {
                        newFormDetails.evaluators = parsedEvaluators;
                    }
                    if (Array.isArray(parsedDocTypes)) {
                        newFormDetails.document_types = parsedDocTypes;
                    }
                } catch (e) {
                    console.warn("Could not parse Form 4 complex data from request body.");
                }
                break;
            case 6: // ⭐ Form 6: อัปเดตข้อมูลคณะกรรมการสอบ
                newFormDetails.committee = newFormDetails.committee || {};
                newFormDetails.committee.chair_id = updatedData.committeeChair;
                newFormDetails.committee.co_advisor2_id = updatedData.coAdvisor2;
                newFormDetails.committee.member5_id = updatedData.committeeMember5;
                newFormDetails.committee.reserve_external_id = updatedData.reserveExternal;
                newFormDetails.committee.reserve_internal_id = updatedData.reserveInternal;
                break;   

            case 7: // ยื่นผลสอบภาษาอังกฤษ ป.เอก
            case 8: // ยื่นผลสอบภาษาอังกฤษ ป.โท
                newFormDetails.exam_type = updatedData.exam_type;
                newFormDetails.exam_date = updatedData.exam_date;
                newFormDetails.reading_score = updatedData.reading_score;
                newFormDetails.listening_score = updatedData.listening_score;
                newFormDetails.total_score = updatedData.total_score;
                newFormDetails.result = updatedData.result;
            break;

            case 9: // ยื่นผลสอบวัดคุณสมบัติ
               newFormDetails.exam_date = updatedData.exam_date;
               newFormDetails.result = updatedData.result;
               break;
            // ... other cases
        }

        await pool.query(
            `UPDATE document_submissions SET form_details = $1, student_comment = $2, status_id = $3, submission_date = NOW(), admin_comment = NULL, action_date = NULL WHERE id = $4`,
            [JSON.stringify(newFormDetails), updatedData.student_comment, NEXT_ADMIN_REVIEW_STATUS_ID, documentId]
        );
        
        await pool.query(`DELETE FROM approval_tasks WHERE submission_id = $1`, [documentId]);
        await pool.query(
            `INSERT INTO submission_logs (submission_id, actor_user_id, action, log_comment) VALUES ($1, $2, 'นักศึกษาส่งเอกสารกลับมาแก้ไข', $3)`,
            [documentId, userId, updatedData.student_comment || '']
        );
        
        const adminUsers = await pool.query(`SELECT id FROM users WHERE role_id = (SELECT id FROM roles WHERE role_name = 'admin')`);
        for (const admin of adminUsers.rows) {
            await pool.query('INSERT INTO approval_tasks (submission_id, approver_user_id, status) VALUES ($1, $2, $3)', [documentId, admin.id, 'pending']);
        }

        res.json({ message: 'แก้ไขและส่งเอกสารกลับมาตรวจสอบใหม่สำเร็จ!' });

    } catch (error) {
        console.error(`Error updating document ${documentId}:`, error);
        res.status(500).json({ message: 'Server Error' });
    }
});



// 5. สั่งให้ Server เริ่มทำงาน
app.listen(PORT, () => {
  console.log(`🚀 Graduate Tracker API Server is running on http://localhost:${PORT}`);
});

