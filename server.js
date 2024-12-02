import crypto from "crypto";
import express from "express";
import cookieParser from "cookie-parser";
import axios from "axios";
import FormData from "form-data";
// import jwt from "jsonwebtoken";
import { states, createUser, getUser } from "./data.js";
import "dotenv/config";

const PORT = 3001;

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

const LOGIN_CALLBACK = "login/callback", DASHBOARD = "dashboard";

const app = express();

app.use(cookieParser());

app.get("/", (req, res) => res.send("<a href='/login'>Use Google Account</a>"));

app.get("/login", (req, res) => {
    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    const state = crypto.randomBytes(16).toString("hex");
    
    authUrl.searchParams.set("client_id", CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", `http://localhost:${PORT}/${LOGIN_CALLBACK}`);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("scope", "openid email profile https://www.googleapis.com/auth/calendar");
    authUrl.searchParams.set("state", state);

    states.add(state);

    res.redirect(authUrl.toString());
});

app.get(`/${LOGIN_CALLBACK}`, async (req, res) => {
    const { state, code } = req.query;

    if (!states.has(state))
        res.send("<p>Invalid state</p>");
    else {
        states.delete(state);

        const form = new FormData();
        form.append("code", code);
        form.append("client_id", CLIENT_ID);
        form.append("client_secret", CLIENT_SECRET);
        form.append("redirect_uri", `http://localhost:${PORT}/${LOGIN_CALLBACK}`);
        form.append("grant_type", "authorization_code");

        try {
            const gAuth = await axios.post("https://www.googleapis.com/oauth2/v3/token", form, { headers: form.getHeaders() });
            // const jwtPayload = jwt.decode(gAuth.data.id_token);

            const userInfo = await axios.get("https://openidconnect.googleapis.com/v1/userinfo", {
                headers: {
                    Authorization: `Bearer ${gAuth.data.access_token}`
                }
            });

            const sessionId = await createUser(userInfo.data, gAuth.data.access_token, gAuth.data.refresh_token);

            res.cookie("session", sessionId);
            res.redirect(`/${DASHBOARD}`);
        }
        catch (error) {
            console.log(error);
            res.send("Server error");
        }
    }
});

app.get(`/${DASHBOARD}`, async (req, res) => {
    const sessionId = req.cookies.session;

    if (!sessionId)
        res.redirect("/");
    else {
        const user = getUser(sessionId);

        if (!user || !user.sessionId)
            res.redirect("/");
        else {
            res.send(`
                <p style="margin: 0 0 0.5rem 0;">Hello <b>${user.email}</b></p>
                <p style="margin: 0 0 3rem 0;">Your role is: <b>${user.role}</b></p>
                <a href="/milestones" style="display: block; margin-bottom: 0.5rem;">Milestones</a>
                <a href="/calendar" style="display: block; margin-bottom: 3rem;">Calendar</a>
                <a href="/logout">Logout</a>
            `);
        }
    }
});

app.listen(PORT, err => {
    if (err)
        return console.log("Something bad happened", err);

    console.log(`Server is listening on ${PORT}`);
})