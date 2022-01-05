import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotEnv from 'dotenv';

dotEnv.config()

import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';

const db = new Database(
    'clients.db',
    { verbose: console.log }
);

const init1 = db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    email               TEXT NOT NULL UNIQUE,
    password            TEXT NOT NULL,
    full_name           TEXT NOT NULL,
    amount_in_account   INTEGER NOT NULL
);`);

const init2 = db.prepare(`CREATE TABLE IF NOT EXISTS transactions (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id              INTEGER,
    amount               FLOAT NOT NULL,
    currency             STRING,
    receiver_or_sender   STRING,
    completed_at         STRING,
    is_positive          INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
);`)

init1.run();
init2.run();

const app = express();
app.use(express.json());
app.use(cors());

const findUserByEmail = db.prepare(`SELECT * FROM users WHERE email=?;`)
const findUserById = db.prepare(`SELECT * FROM users WHERE id=?;`);
const createUser = db.prepare(`INSERT INTO users (email, full_name, password, amount_in_account) VALUES (?, ?, ?, ?);`);

const createFauxTransaction = db.prepare(`INSERT INTO transactions (user_id, amount, currency, receiver_or_sender, completed_at, is_positive) VALUES (?, ?, ?, ?, ?, ?);`);
const findTransactionsByUserId = db.prepare(`SELECT * FROM transactions WHERE user_id=?;`);


const getCamelCasedBankingInfoForUser = (userId) => {
    const user = findUserById.get(userId);
    if (!user) return null;

    const transactions = findTransactionsByUserId.all(user.id);

    return {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        amountInAccount: user.amount_in_account,

        transactions: transactions.map(transaction => ({
            completedAt: transaction.completed_at,
            isPositive: Boolean(transaction.is_positive),
            amount: transaction.amount,
            currency: transaction.currency,
            receiverOrSender: transaction.receiver_or_sender
        })),
    };
}

app.post('/register', (req, res) => {
    try {
        const { email, password, full_name } = req.body;

        if (!(email && password && full_name)) return res.status(400).json({ error: "All inputs are required" });

        const existingUser = findUserByEmail.get(email);
        if (existingUser) return res.status(400).json({ error: 'Bank account already exists!' });

        const encryptedPassword = bcrypt.hashSync(password, 10);
        const { lastInsertRowid } = createUser.run(email, full_name, encryptedPassword, Math.random() * 10000);

        createFauxTransaction.run(lastInsertRowid, Math.random() * 10000, 'USD', 'Someone else', new Date().toISOString(), 1);
        createFauxTransaction.run(lastInsertRowid, Math.random() * 10000, 'GBP', 'Someone else', new Date().toISOString(), 0);
        createFauxTransaction.run(lastInsertRowid, Math.random() * 10000, 'Roopies', 'Someone else', new Date().toISOString(), 1);

        res.json({ message: "Registered successfully, you can try and log in now." })
    } catch (error) {
        res.status(400).json({ error: "Something went wrong" })
    }
})


app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = findUserByEmail.get(email);

        if (!user) return res.status(400).json({ error: "Missing or incorrect details" });

        const isPasswordCorrect = bcrypt.compareSync(password, user.password);
        if (!isPasswordCorrect) return res.status(400).json({ error: "Missing or incorrect details" });

        const token = jwt.sign({ user_id: user.id }, process.env.JWT_TOKEN);

        return res.json({ token, data: getCamelCasedBankingInfoForUser(user.id) });

    } catch (error) {
        res.status(400).json({ error: "Something went wrong ;/" })
    }
})

app.get('/banking-info', (req, res) => {
    if (!req.headers.authorization) return res.status(400).json({ error: "Please log in." })

    const { authorization } = req.headers;

    const decodedUserObject = jwt.verify(authorization, process.env.JWT_TOKEN);
    if (!decodedUserObject) return res.status(400).json({ error: "Expired or malformed token. Please log in." })

    const user = getCamelCasedBankingInfoForUser(decodedUserObject.user_id);

    if (!user) return res.status(400).json({ error: "Something went wrong with the Token, please log in again." })

    res.json({ data: user });
});


app.listen(3001, () => {
    console.info('listening on port 3001');
});
