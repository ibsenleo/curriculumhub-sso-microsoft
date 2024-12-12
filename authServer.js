import "dotenv/config";
import express from "express";
import axios from "axios";
import crypto from "crypto";
import base64url from "base64url";
import session from "express-session";
import helmet from "helmet";
import { generateJwtForUser, formatEmail, generateSignature, formatName, checkUserExists, getUserAvatar,uploadAvatarToStrapi } from "./utils.js";
import logger from "./config/logger.js";
import { getMaintenanceToken } from "./maintenanceToken.js";

const app = express();
const port = 3001;

// Configuración de la app de Microsoft Entra ID (usa .env para guardar las credenciales)
const clientId = process.env.MICROSOFT_ENTRA_CLIENT_ID;
const tenantId = process.env.MICROSOFT_ENTRA_TENANT_ID;
const redirectUri = process.env.MICROSOFT_ENTRA_REDIRECT_URI;

const strapiUrl = process.env.STRAPI_URL;

// Configuración de Helmet para agregar seguridad
app.use(helmet());

// Configuración de las sesiones
app.use(session({
  secret: "tu_secreto_seguro",
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Cambia a true si usas HTTPS
}));

// Generar PKCE code_verifier y code_challenge
function generateCodeVerifier() {
  return base64url(crypto.randomBytes(32));
}

function generateCodeChallenge(codeVerifier) {
  return base64url(crypto.createHash("sha256").update(codeVerifier).digest());
}

let localMaintToken;


// Ruta para iniciar el flujo de autenticación
app.get("/auth/login", (req, res) => {
  const codeVerifier = generateCodeVerifier(); // Generar un nuevo code_verifier
  req.session.codeVerifier = codeVerifier; // Guardar el code_verifier en la sesión
  const codeChallenge = generateCodeChallenge(codeVerifier); // Generar el code_challenge a partir del code_verifier

  const authUrl = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize?client_id=${clientId}&response_type=code&redirect_uri=${redirectUri}&response_mode=query&scope=openid profile email&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  res.redirect(authUrl);
});

// Ruta de callback después de la autenticación
app.get("/auth/callback", async (req, res) => {
  const { code } = req.query;
  const codeVerifier = req.session.codeVerifier; // Obtener el code_verifier de la sesión

  localMaintToken = await getMaintenanceToken();
  try {
    // Intercambiar el código de autorización por un token de acceso
    const tokenResponse = await axios.post(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      new URLSearchParams({
        client_id: clientId,
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier // Enviar el code_verifier original
      }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { access_token } = tokenResponse.data;

    // Verificar el token (esto devuelve el perfil del usuario)
    const userResponse = await axios.get("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const user = userResponse.data;

    // Verificar si el usuario ya existe en Strapi
    const existingUser = await checkUserExists(formatEmail(user.mail || user.userPrincipalName));

    

    let strapiUser = {
      username:null,
      email: null,
      id:null
    };
    let strapiJwt;
    if (existingUser) {
            
      strapiUser = {...existingUser}
      strapiUser.email = formatEmail(existingUser.email);
      strapiJwt = generateJwtForUser(existingUser);
    
    // CREATING USER
    } else {
     
      const userNames = formatName(user)

      let payload = {
          username: formatEmail(user.userPrincipalName),
          email: formatEmail(user.mail || user.userPrincipalName),
          password: crypto.randomBytes(16).toString("hex"),
          first_name: userNames.firstName,
          last_name: userNames.lastName,
      };


      //IMAGE REALTED
      try {
        const photoResponse = await getUserAvatar(access_token)
        const uploadedAvatar = await uploadAvatarToStrapi(
          localMaintToken, 
          Buffer.from(photoResponse.data), 
          `${user.userPrincipalName}-avatar.jpg`
        );   

        if(uploadedAvatar && uploadedAvatar.id) {
          payload.avatar = uploadedAvatar.id
        }

      } catch (error) {
        logger.warn("No image was found. Continue without avatar...")
      }
      
      // Crear el usuario en Strapi si no existe
      const strapiResponse = await axios.post(
        `${strapiUrl}/api/auth/local/register`,
        payload,
        { headers: { "Content-Type": "application/json" } }
      );
      
      // Obtener el JWT de Strapi para autenticación
      strapiUser = strapiResponse.data.user
      strapiJwt = strapiResponse.data.jwt;
    }

    // Redirigir al cliente con el JWT o mostrarlo
    // res.json({ jwt: strapiJwt, user: strapiUser });
    const signedToken = generateSignature(formatEmail(user.mail || user.userPrincipalName));
    logger.info(`Logging in ${formatEmail(user.mail || user.userPrincipalName)}`)
    res.redirect(`http://localhost:3006/auth/callback?jwt=${strapiJwt}&signature=${signedToken}`);

  } catch (error) {
    logger.error("Error durante la autenticación:", JSON.stringify(error.response?.data || error.message));
    res.status(500).send("Error durante la autenticación");
  }
});

app.listen(port, () => {
  logger.info(`Servidor de autenticación corriendo en http://localhost:${port}`);
});
