const express = require('express')
const path = require('path')
const crypto = require('crypto')
const bcrypt = require('bcrypt')
const db = require('./database')
const cors = require('cors')

const app = express()
const port = 3000

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "alogin.html")));
app.get("/register", (req, res) => res.sendFile(path.join(__dirname, "public", "aregister.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

// ===================================================
// GENERATE API KEY
// ===================================================
app.post('/create', (req, res) => {
  console.log(">>> /create dipanggil")

  try {
    const apiKey = "sk-sm-v1-" + crypto.randomBytes(24).toString("hex").toUpperCase()

    return res.json({
      success: true,
      apiKey
    })

  } catch (error) {
    console.error("Error generate key:", error)
    return res.status(500).json({
      success: false,
      message: "Gagal generate API key"
    })
  }
})


// ===================================================
// SAVE USER + API KEY TANPA HASH
// ===================================================
app.post('/save-user', (req, res) => {
  const { firstName, lastName, email, apiKey } = req.body

  if (!firstName || !lastName || !email || !apiKey) {
    return res.status(400).json({
      success: false,
      message: "Semua field harus diisi"
    })
  }

  console.log(">>> Menyimpan user + API Key:", apiKey)

  const now = new Date()
  const insertKey = "INSERT INTO api_key (`key`, out_of_date) VALUES (?, ?)"

  db.query(insertKey, [apiKey, now], (err, result) => {
    if (err) {
      console.log("Error save apikey:", err)
      return res.status(500).json({ success: false })
    }

    const apiKeyId = result.insertId

    const insertUser = `
      INSERT INTO user (first_name, last_name, email, api_key_id)
      VALUES (?, ?, ?, ?)
    `

    db.query(insertUser, [firstName, lastName, email, apiKeyId], (err2) => {
      if (err2) {
        console.log("Error save user:", err2)
        return res.status(500).json({ success: false })
      }

      res.json({ success: true })
    })
  })
})


// ===================================================
// DELETE USER + DELETE API KEY
// ===================================================
app.delete('/delete-user/:id', (req, res) => {
  const userId = req.params.id

  const getUser = `SELECT api_key_id FROM user WHERE id = ?`

  db.query(getUser, [userId], (err, result) => {
    if (err || result.length === 0) {
      return res.status(404).json({
        success: false,
        message: "User tidak ditemukan"
      })
    }

    const apiKeyId = result[0].api_key_id

    db.query(`DELETE FROM user WHERE id = ?`, [userId], (err2) => {
      if (err2) return res.status(500).json({ success: false })

      db.query(`DELETE FROM api_key WHERE id = ?`, [apiKeyId], (err3) => {
        if (err3) return res.status(500).json({ success: false })

        return res.json({ success: true })
      })
    })
  })
})


// ===================================================
// ADMIN REGISTER
// ===================================================
app.post('/register-admin', async (req, res) => {
  const { email, password } = req.body

  const hash = await bcrypt.hash(password, 10)

  db.query(
    `INSERT INTO admin (email, password) VALUES (?, ?)`,
    [email, hash],
    (err) => {
      if (err) return res.status(500).json({ success: false })
      res.json({ success: true })
    }
  )
})


// ===================================================
// ADMIN LOGIN
// ===================================================
app.post('/login-admin', (req, res) => {
  const { email, password } = req.body

  db.query(`SELECT * FROM admin WHERE email = ?`, [email], async (err, results) => {
    if (err || results.length === 0)
      return res.status(401).json({ success: false })

    const admin = results[0]
    const match = await bcrypt.compare(password, admin.password)

    if (!match) return res.status(401).json({ success: false })

    res.json({ success: true })
  })
})


// ===================================================
// ADMIN DASHBOARD DATA
// ===================================================
app.get('/dashboard-data', (req, res) => {
  const queryUsers = `SELECT * FROM user`
  const queryKeys = `SELECT * FROM api_key`

  db.query(queryUsers, (err, users) => {
    if (err) return res.status(500).json({ success: false })

    db.query(queryKeys, (err2, keys) => {
      if (err2) return res.status(500).json({ success: false })

      const enrichedKeys = keys.map(k => {
        const diff = (new Date() - new Date(k.out_of_date)) / (1000 * 60 * 60 * 24)
        return {
          ...k,
          status: diff > 30 ? 'offline' : 'online'
        }
      })

      res.json({
        success: true,
        users,
        apikeys: enrichedKeys
      })
    })
  })
})


// ===================================================
// RUN SERVER
// ===================================================
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`)
})
