import crypto from "crypto";
import { newEnforcer } from "casbin";

const users = [];
const enforcer = await newEnforcer("./config/rbac_model.conf", "./config/rbac_policy_app.csv");

export const states = new Set();

export async function createUser(user, accessToken, refreshToken) {
    const sessionId = crypto.randomBytes(32).toString("hex");

    users.push({
        name: user.name,
        email: user.email,
        picture: user.picture,
        role: (await enforcer.getRolesForUser(user.email))[0],
        sessionId,
        accessToken,
        refreshToken
    });

    return sessionId;
}

export function getUser(sessionId) {
    return users.find(user => user.sessionId === sessionId);
}
