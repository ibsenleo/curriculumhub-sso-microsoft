import axios
 from "axios";
export let maintenanceToken = null
const strapiUrl = process.env.STRAPI_URL;

export const getMaintenanceToken = async () => {
    if (!maintenanceToken) {
        maintenanceToken = await getStrapiAdminToken()
    }

    return maintenanceToken
}
/**
 * Get Strapi maintenance token
 * @returns 
 */
export const getStrapiAdminToken = async () => {
    try {
      const response = await axios.post(strapiUrl + "/api/auth/local", {
        identifier: process.env.STRAPI_ADMIN_EMAIL,
        password: process.env.STRAPI_ADMIN_PASSWORD,
      });
      return response.data.jwt;
    } catch (error) {
      console.error("Error obteniendo el token del admin:", error);
      throw new Error("No se pudo autenticar al admin");
    }
  }