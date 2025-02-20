import { Router } from "express";
import OAuth from "../middleware/oauth.js";

export const oauthRouter = Router();

const googleClientSecret = process.env["GOOGLE_CLIENT_SECRET"] as string;
const oauth = new OAuth();
oauth.setupProvider("google", {
  baseUrl: "https://oauth2.googleapis.com/token",
  clientSecret: googleClientSecret,
  onSuccess: ({ res, data }) => {
    res.status(200).json(data);
  },
  onFailure: ({ res, error }) => {
    res.status(500).json({ error: error.message });
  },
});

oauthRouter.post("/exchange", oauth.authenticate("google"));
