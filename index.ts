import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";

const accessSecret = "ACCESS_SECRET";
const refreshSecret = "REFRESH_SECRET";

const app = express();
app.use(cors({
    origin: "*"
}));
app.use(express.json());

const port = 8081;

const signAccessToken = (email: string) => jwt.sign({ email: email }, accessSecret, {
    expiresIn: "5m",
})

const verifyRefreshToken = (email: string, token: string) => {
    try {
        const decoded = jwt.verify(token, refreshSecret);
        return decoded['email'] ?? "" === email;
    } catch (err) {
        return false;
    }
}

app.post("/login", (req, res) => {
    const { email } = req.body
    if (!email) {
        return res.status(400).json({
            success: false,
            error: "enter valid credientials"
        })
    }

    const accessToken = signAccessToken(email);
    const refreshToken = jwt.sign({ email: email }, refreshSecret, {
        expiresIn: "60m",
    });

    return res.status(200).json(
        {
            success: true,
            accessToken,
            refreshToken,
            expiry: 5 * 60
        });
});

app.post("/refresh", (req, res) => {
    const { email, token } = req.body;
    const isValid = verifyRefreshToken(email, token);
    if (!isValid) {
        return res
            .status(401)
            .json({ success: false, error: "Invalid token,try login again" });
    }
    const accessToken = signAccessToken(email);
    return res.status(200).json({ success: true, accessToken });
});

app.listen(port, () => {
    console.log(`Listening on port ${port}...`);
});

