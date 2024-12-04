import crypto from "crypto";
import express from "express";
import cookieParser from "cookie-parser";
import axios from "axios";
import FormData from "form-data";
// import jwt from "jsonwebtoken";
import { states, createUser, getUser, ghStates, pdp, setUserGhToken, ghLogout } from "./data.js";
import "dotenv/config";

const PORT = 3001;

const { CLIENT_ID, CLIENT_SECRET, CLIENT_ID_GITHUB, CLIENT_SECRET_GITHUB } = process.env;
const LOGIN_CALLBACK = "login/callback";
const GITHUB_CALLBACK = "github/callback";

const app = express();

app.use(cookieParser());

const verifyAccess = async (req, res, next) => {
    const { path, method } = req;
    const sessionId = req.cookies.session;

    if (sessionId) {
        const user = getUser(sessionId);

        if (user && user.sessionId) {
            if (!(await pdp(user.role, path, method)))
                res.status(401).send("Unauthorized");
            else {
                req.user = user;
                next();
            }

            return;
        }
    }

    res.redirect("/");
}

app.get("/", (_, res) => res.send("<a href='/login'>Use Google Account</a>"));

app.get("/login", (_, res) => {
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
            res.redirect("/dashboard");
        }
        catch (error) {
            console.log(error);
            res.send("Server error");
        }
    }
});

app.get("/dashboard", verifyAccess, async (req, res) => {
    const { user } = req;

    res.send(`
        <div style="margin-bottom: 2rem; display: flex;">
            <img src="${user.picture}" style="margin-right: 1rem; border-radius: 1rem;" />
            <div>
                <p style="margin: 0 0 0.5rem 0;">Hello <b>${user.name} (${user.email})</b></p>
                <p style="margin: 0;">Your role is: <b>${user.role}</b></p>
            </div>
        </div>
        <form action="/milestones">
            <input type="text" name="repo" placeholder="Repository URL" style="width: 20rem;" />
            ${!user.ghToken ? `
                <a href="/github" style="margin-left: 0.5rem;">Login with GitHub</a>
            ` : ""}
            <input type="submit" style="display: block; margin-top: 0.5rem;" />
        </form>
        <a href="/logout" style="display: block; margin-top: 3rem;">Logout</a>
        ${user.ghToken ? `
            <a href="/logout/github" style="display: block; margin-top: 0.5rem;">Logout GitHub</a>
        ` : ""}
    `);
});

app.get("/github", verifyAccess, (_, res) => {
    const authUrl = new URL("https://github.com/login/oauth/authorize");
    const state = crypto.randomBytes(16).toString("hex");
    
    authUrl.searchParams.set("client_id", CLIENT_ID_GITHUB);
    authUrl.searchParams.set("redirect_uri", `http://localhost:${PORT}/${GITHUB_CALLBACK}`);
    authUrl.searchParams.set("scope", "repo");
    authUrl.searchParams.set("state", state);

    ghStates.add(state);

    res.redirect(authUrl.toString());
});

app.get(`/${GITHUB_CALLBACK}`, verifyAccess, async (req, res) => {
    const { state, code } = req.query;

    if (!ghStates.has(state))
        res.send("<p>Invalid state</p>");
    else {
        ghStates.delete(state);

        const body = JSON.stringify({
            code,
            client_id: CLIENT_ID_GITHUB,
            client_secret: CLIENT_SECRET_GITHUB,
            redirect_uri: `http://localhost:${PORT}/${GITHUB_CALLBACK}`
        });

        try {
            const ghAuth = await axios.post("https://github.com/login/oauth/access_token", body, { headers: { "Accept": "application/json", "Content-Type": "application/json" } });
            setUserGhToken(req.cookies.session, ghAuth.data.access_token);

            res.redirect("/dashboard");
        }
        catch (error) {
            console.log(error);
            res.send("Server error");
        }
    }
});
app.get("/logout", verifyAccess, (_, res) => {
    res.clearCookie("session");
    res.redirect("/");
});

app.get("/logout/github", verifyAccess, (req, res) => {
    ghLogout(req.cookies.session);
    res.redirect("/dashboard");
});

app.listen(PORT, err => {
    if (err)
        return console.log("Something bad happened", err);

    console.log(`Server is listening on ${PORT}`);
})