import winston from "winston";

export default winston.createLogger({
    level:"info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
        winston.format.colorize()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({filename: "logs/app.log"})
    ],
})