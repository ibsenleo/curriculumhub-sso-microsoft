// const jwt = require('jsonwebtoken');
import jwt from 'jsonwebtoken'
import axios from 'axios';
import { getMaintenanceToken } from './maintenanceToken.js';

const strapiUrl = process.env.STRAPI_URL;

export const generateJwtForUser = (user) => {
  // Aquí utilizas la clave secreta de JWT de Strapi
  const strapiSecret = process.env.STRAPI_JWT_SECRET;
  
  const payload = {
    id: user.id,
    email: user.email,
    username: user.username,
  };

  const token = jwt.sign(payload, strapiSecret, { expiresIn: '7d' }); // Ajustar el tiempo de expiración según sea necesario
  return token;
}

export const formatEmail = (email) =>  { 
  let formattedEmail = email;
  if (email.indexOf('#') > 0) {
    formattedEmail = email.substring(0, email.indexOf('#')).replace('_','@').toLowerCase()
  }

  return formattedEmail;
}

export const formatName = (user) => {
  let name = {
    firstName: null,
    lastName:null
  }
  if (user.givenName) {
    name.firstName = user.givenName
    name.lastName = user.surname || ""
  }
  else 
  {
    if(user.displayName.indexOf(" ")){
      name.firstName = user.displayName.substring(0, user.displayName.indexOf(" "))
      name.lastName = user.displayName.substring(user.displayName.indexOf(" "), user.displayName.length)
    }
  }
  return name;
}

export const generateSignature = (email) => {
    return jwt.sign(
    { email: email },
    process.env.SHARED_SIGNATURE, // El secreto compartido
    { expiresIn: '5m' } );// El token puede tener una expiración corta
}

/**
 * Verifies if user exists
 * @param {*} userEmail 
 * @returns 
 */
export const checkUserExists = async (userEmail) => {
  try {
    const maintenanceUserToken = await getMaintenanceToken()

    const encodedUserEmail = userEmail.replace(/#/g, '%23').toString().toLowerCase();
    const response = await axios.get(`${strapiUrl}/api/users?filters[email][$eq]=${encodedUserEmail}`, {
      headers: {
        Authorization: `Bearer ${maintenanceUserToken}` // Usa el token del usuario de mantenimiento para autenticar la solicitud
      }
    });
    return response.data.length > 0 ? response.data[0] : null;
  } catch (error) {
    console.error("Error al verificar si el usuario existe:" + (error.response?.data || error.message));
    throw new Error("Error verificando la existencia del usuario");
  }
}

/**
 * Get user avatar from ms service
 * @param {*} access_token 
 * @returns 
 */
export const getUserAvatar = async (access_token) => {
  // Obtener la imagen de perfil del usuario
  let avatarUrl = null;
  try {
    const photoResponse = await axios.get("https://graph.microsoft.com/v1.0/me/photo/$value", {
      headers: { Authorization: `Bearer ${access_token}` },
      responseType: 'arraybuffer' // Asegura que se obtiene la respuesta en binario
    });

    // Convertir la imagen a base64 para almacenarla o usarla en tu app
    const avatarBase64 = Buffer.from(photoResponse.data, 'binary').toString('base64');
    avatarUrl = `data:image/jpeg;base64,${avatarBase64}`;
  } catch (photoError) {
      logger.error("Error obtaining user avataar from microsoft: " + photoError.message);
      throw new Error("Error obtaining user avatar from microsoft")
    // No es obligatorio tener una imagen de perfil; se puede dejar null
  } 
  return avatarUrl;
}

/**
 * Upload image to strapi
 * @param {*} accessToken 
 * @param {*} buffer 
 * @param {*} fileName 
 * @returns 
 */
export const uploadAvatarToStrapi = async (accessToken, buffer, fileName) => {
  try {
    const formData = new FormData();
    formData.append('files', buffer, {
      filename: fileName,
      contentType: 'image/jpeg',
    });

    const response = await axios.post(`${strapiUrl}/api/upload`, formData, {
      headers: {
        ...formData.getHeaders(),
        Authorization: `Bearer ${accessToken}`,
      },
    });

    return response.data[0]; // Devolver la respuesta del archivo subido
  } catch (error) {
    console.error("Error subiendo la imagen a Strapi:" + (error.response?.data || error.message));
    throw new Error("Error al subir la imagen del avatar");
  }
}