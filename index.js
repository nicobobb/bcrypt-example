import bcrypt from 'bcrypt'
const saltRounds = 10
// Número de rondas para generar el salt.
// Es una cadena aleatoria que se concatena a la contraseña antes de aplicar el algoritmo de hash.

// Función para hashear una contraseña
async function hashPassword(plainTextPassword) {
    try {
        const salt = await bcrypt.genSalt(saltRounds)
        const hashedPassword = await bcrypt.hash(plainTextPassword, salt)
        return hashedPassword
    } catch (error) {
        throw error
    }
}

// Función para verificar una contraseña hasheada
async function comparePasswords(plainTextPassword, hashedPassword) {
    try {
        const isMatch = await bcrypt.compare(plainTextPassword, hashedPassword)
        return isMatch
    } catch (error) {
        throw error
    }
}

// Ejemplo de uso
;(async () => {
    const myPlaintextPassword = '123456'

    // Hashear la contraseña
    try {
        const hashedPassword = await hashPassword(myPlaintextPassword)
        console.log('Contraseña hasheada:', hashedPassword)

        // Verificar la contraseña
        const isMatch = await comparePasswords('123456', hashedPassword)
        console.log('¿La contraseña coincide?', isMatch)
    } catch (error) {
        console.error('Error:', error)
    }
})()
