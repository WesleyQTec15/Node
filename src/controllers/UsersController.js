const { hash, compare } = require("bcryptjs")

const AppError = require("../utils/AppError")

const sqliteConnection = require("../database/sqlite")

class UsersController {
    async create(request, response){
        const { name, email, password } = request.body

        const database = await sqliteConnection();

        const checkUserExists = await database.get("SELECT * FROM users WHERE email = (?)", [email])

        if(checkUserExists){
            throw new AppError("Este e-mail já esta em uso.")
        }

        const hashedpassword = await hash(password, 8)

        await database.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedpassword])

        return response.status(201).json()
    }

    async update(request, response){
        const {name, email, password, oldPassword} = request.body;
        const { id } = request.params;

        const database = await sqliteConnection();

        const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);
        if(!user){
            throw new AppError("Usúario não encontrado");
        }

        const userWithUpdatedEmail = await database.get("SELECT * FROM users WHERE email = (?)", [email]);

        if(userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id){
            throw new AppError("Este email já esta em uso.");
        }
        
        user.name = name ?? user.name;
        user.email = email ?? user.name;
        
        if( password && !oldPassword){
            throw new AppError("Você precisa informar a senha antiga para redefinir sua senha");
        }

        if(password && oldPassword){
            const checkOldPassword = compare(oldPassword, user.password)
            if(!checkOldPassword){
                throw new AppError("A senha esta errada!")
            }

            user.password = await hash(password, 8);
        }

        await database.run(`
        UPDATE users SET
        name = ?,
        email = ?,
        password = ?,
        updated_at = DATETIME('now')
        WHERE id = ?`,
        [user.name, user.email, user.password, id]
        )

        return response.json()
    }

}

module.exports = UsersController