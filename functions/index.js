/**
 * Import function triggers from their respective submodules:
 *
 * const {onCall} = require("firebase-functions/v2/https");
 * const {onDocumentWritten} = require("firebase-functions/v2/firestore");
 *
 * See a full list of supported triggers at https://firebase.google.com/docs/functions
 */

const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");

const functions = require("firebase-functions");
const formidable = require("formidable-serverless");
const firebase = require("firebase-admin");
const { v4: uuidv4 } = require("uuid");
const sharp = require("sharp");
const jwt = require("jsonwebtoken");

const cors = require("cors")({
  origin: true,
  methods: ["POST", "GET", "DELETE", "PUT", "PATCH"],
});

const corsAuth = require("cors")({
  credentials: false,
  origin: "*",
  methods: ["POST", "GET", "DELETE", "PUT", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept", "Origin"],
});

const { Storage } = require("@google-cloud/storage");

firebase.initializeApp();

exports.uploadFile = functions.https.onRequest((req, res) => {
  corsAuth(req, res, () => {
    let form = new formidable.IncomingForm();

    form.parse(req, async (err, fields, files) => {
      const values = Object.values(files);
      let file = values[0];
      if (!file) {
        reject(new Error("no file to upload, please choose a file."));
        return;
      }

      const storage = new Storage({
        keyFilename: "service-account.json",
      });

      let filePath = file.path;

      const image = sharp(filePath);
      image
        .metadata()
        .then(() => {
          return image.resize({ width: 720 }).toFormat("png").toBuffer();
        })
        .then((buffer) => {
          let uuid = uuidv4();
          const response = storage.bucket("default_bucket");
          const fileToUpload = response.file(uuid + ".png");
          fileToUpload.createWriteStream().end(buffer);
          res.status(200).json("Success");
        })
        .catch((error) => {
          res.status(500).json(error);
        });
    });
  });
});

exports.singup = functions.https.onRequest((req, res) => {
  cors(req, res, () => {
    firebase
      .auth()
      .createUser({ email: req.body.email, password: req.body.password })
      .then((userRecord) => {
        console.log("Successfully created new user:", userRecord.uid);
        const userToken = {
          id: userRecord.uid,
          email: userRecord.email,
        };

        const token = jwt.sign(userToken, process.env.SECRET_TOKEN, {
          expiresIn: 60 * 60, // Expira en una hora
        });
        return res.status(200).send({ user: userToken, token: token });
      })
      .catch((error) => {
        console.log("Error creating new user:", error);
        return res.status(500).send({ error: error });
      });
  });
});

exports.login = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {
    const { email, password } = req.body;
    try {
      const userRecord = await firebase.auth().getUserByEmail(email);
      const passwordIndex = userRecord.passwordHash.indexOf("password=");
      const extractedPassword = userRecord.passwordHash.substring(
        passwordIndex + 9
      );
      if (extractedPassword.localeCompare(password) === 0) {
        const userToken = {
          id: userRecord.uid,
          email: userRecord.email,
        };
        const token = jwt.sign(userToken, process.env.SECRET_TOKEN, {
          expiresIn: 60 * 60,
        });
        res.status(200).json({ user: userToken, token: token });
      } else {
        res.status(401).json({ error: "Credenciales inválidas" });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  });
});

const tokenAuth = (req, res, next) => {
  console.log(req.headers);
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.status(401).json({ error: "Token missing" });
  try {
    const decoded = jwt.verify(token, process.env.SECRET_TOKEN);
    req.user = decoded;
    next();
  } catch (error) {
    console.log(error);
    return res.status(403).json({ error: "Invalid token" });
  }
};

exports.getImgs = functions.https.onRequest(async (req, res) => {
  cors(req, res, async () => {
    tokenAuth(req, res, async () => {
      const storage = new Storage({
        keyFilename: "service-account.json",
      });

      const [files] = await storage.bucket("default_bucket").getFiles();
      const filesToReturn = files.map((file) => file.metadata);
      res.status(200).send(filesToReturn);
    });
  });
});

exports.deleteFile = functions.https.onRequest(async (req, res) => {
  cors(req, res, async () => {
    tokenAuth(req, res, async () => {
      try {
        const storage = new Storage({
          keyFilename: "service-account.json",
        });
        console.log(req.body.fileName);
        const fileName = req.body.fileName;
        console.log(fileName);
        const file = await storage
          .bucket("default_bucket")
          .file(fileName)
          .delete();

        if (!file) {
          res.status(404).send("File not found");
        }
        res.status(200).send("File deleted");
      } catch (error) {
        res.status(500).send("Internal server error");
      }
    });
  });
});
