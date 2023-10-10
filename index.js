const express = require("express")
const {body, validationResult} = require("express-validator")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const {param} = require("express-validator")
const app = express()
const secretKey = 'mysecretkey'

app.use(express.json())

let users = [];
let userIdCounter = 1;

app.post('/auth/register', [
    //validasi fullname
    body('fullName').notEmpty().withMessage('Nama wajib diisi'),
    
    //validasi email
    body('email').notEmpty().withMessage('Email wajib diisi').isEmail().withMessage('Email tidak valid'),
    
    //validasi password
    body('password').notEmpty().withMessage('Password wajib diisi')
    .isLength({ min: 8 }).withMessage('Password minimal 8 karakter')
    .isStrongPassword({ minSymbols: 1 }).withMessage('Password harus mengandung minimal satu simbol'),
   
    // validasi bio (dapat dikosongkan)
    body('bio') .optional(),
    
    // validasi DoB (memiliki format tanggal)
    body('dob').notEmpty().withMessage('Date of Birth wajib diisi')
    .isDate({ format: 'YYYY-MM-DD' }).withMessage('Format tanggal tidak valid (YYYY-MM-DD)'),
    ], (req, res) => {
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            message: 'Validasi Error', 
            detail: errors.array()
        })
    }

    const { fullName, email, password, bio, dob } = req.body;

    if (users.some(user => user.email === email)) {
        return res.status(400).json({
            message: 'Email sudah pernah terdaftar.'
        })
      }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const user = {
        id: userIdCounter++,
        fullName,
        email,
        password: hashedPassword,
        bio,
        dob
    }

    users.push(user);

    res.status(201).json({
        message: 'Registrasi success'
    })
});

app.post('/auth/login', [
    //validasi email
    body('email')
    .notEmpty().withMessage('Email wajib diisi')
    .isEmail().withMessage('Email tidak valid'),
    
    //validasi password
    body('password')
    .notEmpty().withMessage('Password wajib diisi')
    .isLength({ min: 8 }).withMessage('Password minimal 8 karakter')
    .matches(/[\W]/).withMessage('Password harus memiliki minimal 1 simbol'),
    ], (req, res) => {
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
            message: 'Validasi Error',
            detail: errors.array()
        })
    }
  
    const { email, password } = req.body;
  
    const user = users.find(user => user.email === email);
    if (!user) {
      return res.status(401).json({
            message: 'Login failed'
        })
    }
  
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
            message: 'Login failed'
        })
    }

    const token = jwt.sign({ id: user.id, email: user.email }, secretKey);
  
    res.status(200).json({
        message: 'Success',
        data: { token }
    })
});

app.get('/users', (req, res) => {
    if (users.length === 0) {
      return res.status(404).json({
            message: 'User Not Found'
        })
    }
  
    const userData = users.map(user => ({
      fullName: user.fullName,
      email: user.email,
      bio: user.bio,
      dob: user.dob
    }))
  
    res.status(200).json({
        message: 'Success',
        data: userData
    })
});
  
app.get('/users/:userId', [
    param('userId')
        .isNumeric().withMessage('User ID wajib berbentuk angka'),
    ], (req, res) => {
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
            message: 'Validasi error',
            detail: errors.array()
        })
    }
  
    const userId = parseInt(req.params.userId, 10);
    const user = users.find(user => user.id === userId);
  
    if (!user) {
      return res.status(404).json({
            message: 'User Not Found' 
        })
    }
  
    const userData = {
      fullName: user.fullName,
      email: user.email,
      bio: user.bio,
      dob: user.dob
    }
  
    res.status(200).json({
        message: 'Success',
        data: userData
    })
});

app.listen(1945, ()=> {
    console.log(`app start at http://localhost:1945`)
})