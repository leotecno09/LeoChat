const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const socketIO = require('socket.io');
const io = socketIO(server);
// const axios = require('axios')
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const WebSocket = require('ws');
const session = require('express-session');
const { create } = require('express-handlebars');
const fs = require('fs');
const path = require('path');
const flash = require('connect-flash');
const nodemailer = require('nodemailer');
const crypto = require('crypto');


const wss = new WebSocket.Server({ port: 8080 });

const pool = new Pool({
    user: 'postgres',
    host: '10.0.0.109',
    database: 'postgres',
    password: '1',
    port: 5432,
});

// const options = {
//    useNewUrlParser: true,
//    useUnifiedTopology: true
// };

// const client = new MongoClient(uri, {
//    serverApi: {
//        version: ServerApiVersion.vl,
//        strict: true,
//        deprecationErrors: true,
//    }
// });

//    async function run() {
//        try {
//            await client.connect();
//            await client.db("admin").command({ ping: 1 });
//            console.log("[MongoDB] Pinged your deployment. You succefully connected to MongoDB!");
//        } finally {
//            await client.close();
//        }
//    }
//    run().catch(console.dir);

pool.connect((error, client, release) => {
    if (error) {
        console.error('Error:', error);
        return;
    }

    console.log('[INFO] The server is connected to PostgreSQL DB!');
    release();
});

app.use(
    session({
        secret: 'akeifjskadkeoifksaklxmje',
        resave: false,
        saveUninitialized: true
    })
)

app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(flash());

const hbs = create({
    extname: '.hbs',
    defaultLayout: false
    // layoutsDir: path.join(__dirname, 'assets', 'templates'),
});
app.engine('.hbs', hbs.engine);
app.set('view engine', '.hbs');

// const templatePath = path.join(__dirname + '/assets/templates');
// console.log(templatePath);

// function loadTemplate(templateName) {
//   const templateContent = fs.readFileSync('${templatePath}/${templateName}.hbs', 'utf-8');
//    return handlebars.compile(templateContent);
// }

const blockDirectAccess = (req, res, next) => {
    if (!req.headers.referer || !req.headers.referer.includes('/account/login')) {
        res.status(403).send("403: Method not allowed");
    } else {
        next();
    }
};

// AUTENTICAZIONE A DUE FATTORI
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'leochat944@gmail.com',
        pass: 'xxxxxxxxxxxxx',
    },
});

const generateCode = () => {
    return Math.floor(100000 + Math.random() * 900000);
};

const createEmailMessage = (code) => {
    return `
        <p>Ciao,</p>
        <p>Il tuo codice di autenticazione è: ${code}</p>
        <p>Grazie!</p>
    `;
};

const sendEmail = async (email, subject, message) => {
    try {
        const info = await transporter.sendMail({
            from: 'leochat944@gmail.com',
            to: email,
            subject: subject,
            html: message,
        });
        console.log('[2FA System] Email inviata:', info.response);
    } catch (error) {
        console.error('[2FA System] Errore durante l\'invio della mail:', error);
    }
};

const saveCode = async (code, username) => {
    try {
        // const expiresAt = new Date(Date.now() + 3 * 60 * 1000);

        await pool.query('INSERT INTO login_codes (code, session, created_at) VALUES ($1, $2, NOW()::timestamp)', [code, username]);

        console.log('[2FA System] Codice salvato nel database.');
    } catch (error) {
        console.error('[2FA System] Errore durante il salvataggio del codice:', error);
    }
};

const deleteExpiredCodes = async () => {
    try {
        await pool.query("DELETE FROM login_codes WHERE created_at <= NOW() - interval '3 minutes'");

        console.log('[2FA System] Codici scaduti cancellati');
    } catch (error) {
        console.error('[2FA System] Errore durante la cancellazione dei codici scaduti:', error);
    }
};

setInterval(deleteExpiredCodes, 60 * 1000);
//FINE AUTENTICAZIONE A DUE FATTORI

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/assets/templates/index.html');
});

app.get('/account/register', (req, res) => {
    // res.sendFile(__dirname + '/assets/templates/register.html');
    res.render('register', { message: req.flash('error') });
});

app.post('/account/register', async (req, res) => {
    const username = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    const passwordConfirm = req.body.passwordConfirm;
    const checkbox = req.body.checkbox !== undefined;
    function generateRandomNumber(numDigits) {
        var min = Math.pow(10, numDigits - 1);
        var max = Math.pow(10, numDigits) - 1;
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    const userid = generateRandomNumber(10);

    pool.query('SELECT * FROM users WHERE userid = $1', [userid], (error, results) => {
        if (error) {
            res.status(500).send('Server error');
            console.error('[ERROR] Error during query execution:', error);
        } else {
            if (results && results.rows && results.rows.length > 0) {
                return generateRandomNumber;
            }           
        }
    });

    if (checkbox) {

        if (password === passwordConfirm) {
            const hashedPassword = await bcrypt.hash(password, 10);

            pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email], (error, results) => {
                if (error) {
                    console.error('[ERROR] Error during query execution:', error);
                    res.status(500).send('Server error');
                }

                else {
                    if (results && results.rows && results.rows.length > 0) {
                        const errorMessage = true;
                        const message = "Un utente con questa email/username esiste già!";
                        const data = { errorMessage, message };
                        res.render('register', data);
                    }

                    else {
                        const role = 'User';
                        pool.query('INSERT INTO users (username, email, password, userid, role) VALUES ($1, $2, $3, $4, $5)', [username, email, hashedPassword, userid, role], (error) => {
                           if (error) {
                                console.error('[ERROR] Error during query execution:', error);
                                res.status(500).send('Server error!');
                           }

                           else {
                                const firstJoin = true; //DA RIVEDERE LA FUNZIONE FIRSTJOIN!!!
                                const username = req.session.user;
                                const data = { firstJoin, username };
                                res.render('dashboard', data);
                                console.log('[POST] Post request, a new account was posted in PostgreSQL database!');
                           }
                        });
                    }
                }
            });

        } else {
            // ws.send(JSON.stringify({ title: "Error", message: "The two passwords doesn't match!", type: "fail"}));
            const errorMessage = true;
            const message = "Le due password non corrispondono!"
            const data = { errorMessage, message };
            res.render('register', data);
        }
    } else {
        const errorMessage = true;
        const message = "Perfavore, accetta i termini di servizio!"
        const data = { errorMessage, message };
        res.render('register', data);
    }
});

app.get('/account/login', (req, res) => {
    // res.sendFile(__dirname + '/assets/templates/login.html');
    res.render('login', { message: req.flash('error') });
});

app.post('/account/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    pool.query('SELECT * FROM users WHERE email = $1 OR username = $1', [email], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error!');
        }

        if (!results || !results.rows || results.rows.length === 0) {
            const errorMessage = true;
            const message = "Email o username errati!"
            const data = { errorMessage, message };
            res.render('login', data)
        } else {
            const user = results.rows[0];
            bcrypt.compare(password, user.password, (error, results) => {
                if (error) {
                    console.error('Error during credential verify:', error);
                    res.status(500).send('Server error'); 
                }
    
                if (results) {
                    const twoStepVerification = user.two_step_verification;

                    if (twoStepVerification === 'true') {
                        const username = user.username;

                        const redirectURL = `/account/2falogin?username=${encodeURIComponent(username)}`;
                        res.redirect(redirectURL);
                    } else {
                        // console.log(results);
                        req.session.user = user.username;
                        res.redirect('/myDashboard');
                    }
                } else {
                    console.log(results);
                    const errorMessage = true;
                    const message = "Password errata!"
                    const data = { errorMessage, message };
                    res.render('login', data)
                }
            });
        }
    });
});

/// app.use('/account/2falogin', blockDirectAccess);

app.get('/account/2falogin', (req, res) => {
    const username = req.query.username;
    const data = { username }
    console.log(username);

    res.render('2falogin', data);

    pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
        if (error) {
            console.error('Error during credential verify:', error);
            res.status(500).send('Server error');             
        } else {
            const userEmail = results.rows[0].email;

            pool.query('SELECT * FROM login_codes WHERE session = $1', [username], (error, results) => {
                if (error) {
                    console.error('[ERROR] Error during query execution:', error);
                    res.status(500).send('Server error');                     
                }
        
                if (!results || !results.rows || results.rows.length === 0) {
                    const code = generateCode();
                    saveCode(code, username)
        
                    const emailMessage = createEmailMessage(code);
                
                    const subject = 'Codice di autenticazione';
                    const recipientEmail = userEmail;
                
                    sendEmail(recipientEmail, subject, emailMessage);
                } else {
                    console.log('[2FA System] Codice per sessione', username, 'già esistente');
                }
            });  
        }
    });   
});

app.post('/account/2falogin', (req, res) => {
    const username = req.body.username;
    console.log(username);
    const formCode = req.body.code;

    pool.query('SELECT * FROM login_codes WHERE session = $1', [username], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error');          
        } else {
            const code = results.rows[0].code;

            if (formCode === code) {
                pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
                    if (error) {
                        console.error('[ERROR] Error during query execution:', error);
                        res.status(500).send('Server error');                        
                    } else {
                        const user = results.rows[0];
                        req.session.user = user.username;
                        res.redirect('/myDashboard');
                        pool.query('DELETE FROM login_codes WHERE session = $1', [username], (error, results) => {
                            if (error) {
                                console.error('[ERROR] Error during query execution:', error);
                                res.status(500).send('Server error');                                  
                            } else {
                                console.log('[2FA System] Codice di autenticazione di', username, 'cancellato')
                            }
                        });
                    }
                });
            } else {
                console.log('[2FA System] Errore durante l\'accesso')
                const errorMessage = true;
                const message = "Il codice inserito è errato!";
                const data = { errorMessage, message };
        
                res.render('login', data);
            }
        }
    });   
});

app.get('/myDashboard', (req, res) => {
    if (req.session.user) {
        const username = req.session.user;
        const messages = true;

        //RECUPERA MESSAGGI DAL DATABASE
        pool.query('SELECT * FROM messages', (error, results) => {

            const rows = results.rows;

            if (error) {
                console.error('[ERROR] Error during query execution:', error);
            }

            if (!results || !results.rows || results.rows.length === 0) {
                const data = { username }
                res.render('dashboard', data)
            }

            const messagesData = [];

            rows.forEach(row => {                   //FARE SISTEMA DI CANCELLAZIONE AUTOMATICA DOPO TRE GIORNI E ANDARE AVANTI CON LE SESSIONI DELLE CHAT, AGGIUNGERE MONGODB ECC...
                const messageTitle = row.title;
                const messageSender = row.sender;
                const messageText = row.text;
                const btnValue = row.buttonvalue;
                const btnTitle = row.buttontitle;
                const btnLink = row.buttonlink;
                const curDate = row.date;
                console.log(btnValue);

                messagesData.push({
                    messageTitle,
                    messageSender,
                    messageText,
                    btnValue,
                    btnTitle,
                    btnLink,
                    curDate
                });
            });

            // console.log(messagesData);
            const data = { username, messages: messagesData };
            res.render('dashboard', data);
        });
    } else {
        res.redirect('/account/login');
    }
});

app.get('/testMessage', (req, res) => {
    res.sendFile(__dirname + '/assets/templates/messtestpage.html');
});

app.get('/chats', (req, res) => {
    if (req.session.user) {
        const username = req.session.user;
        const chats = false;
        const data = { username, chats };
        res.render('chats', data);
    } else {
        res.redirect('/account/login');
    }
});

app.get('/chats/:chatCode', async (req, res) => {
    if (req.session.user) {
        const username = req.session.user;
        const chats = false;
        const chatCode = req.params.chatCode;

        if (isNaN(chatCode)) {
            const error = "Il codice chat è invalido!";
            const errorFormatted = { error }
            res.render('generalError', errorFormatted);
            return;
        }

        pool.query("SELECT name, owner FROM chats WHERE code = $1", [chatCode], (error, results) => {
            if (error) {
                console.error('[ERROR] Error during query execution: ', error);
                res.status(500).send('Server error!');
            }

            if (!results || !results.rows || results.rows.length === 0) {
                const error = "La chat non esiste più o il codice è invalido.";
                const errorFormatted = { error }
                res.render('generalError', errorFormatted);
            }

            else {
                const chatOwner = results.rows[0].owner;
                const chatName = results.rows[0].name;
                const group = true;
                const data = { username, chats, chatName, chatOwner, group };
                res.render('chat', data);
            }
        });
        // const chatOwner = results.rows[0].owner;
        // const chatName = results.rows[0].name;
    } else {
        res.redirect('/account/login');
    }
});

app.get('/admin/SendMessage', (req, res) => {
    const username = req.session.user;

    pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
        if (error) {
            console.log('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error!');
        } else {
            const role = results.rows[0].role;
            if (role === 'User') {
                const error = 'Non puoi accedere a questa pagina!';
                const errorFormatted = { error };
                res.render('generalError', errorFormatted);
            }
        }
    });
    res.render('adminSenderNotification');
});

app.post('/admin/SendMessage', (req, res) => {
    const messTitle = req.body.title;
    const messSender = req.body.sender;
    const text = req.body.text;
    const btnValue = req.body.buttonEnabler !== undefined;
    const btnTitle = req.body.btnTitle;
    const btnLink = req.body.btnLink;

    pool.query("INSERT INTO messages (title, sender, text, buttonvalue, buttontitle, buttonlink, date) VALUES ($1, $2, $3, $4, $5, $6, TO_CHAR(NOW(), 'DD-MM-YYYY HH24:MI'))", [messTitle, messSender, text, btnValue, btnTitle, btnLink], (error) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
        }

        else {
            res.redirect('/myDashboard');
        }
    });
});

//SISTEMA DI CHAT --- https://chat.openai.com/c/292fcc62-aebf-4af8-a87e-92fc3bd1d3f0 FINIREEEEEEEEEEEEEEE

const chatRooms = new Map();
const usersInChat = new Map();

io.on('connection', (socket) => {
    console.log('[+] User connected!');
    socket.on('disconnect', () => {
        console.log('[-] User disconnected!')
    });

    socket.on('createChat', (chatId, chatName) => {
        chatRooms.set(chatId, chatName)                     //maybe da fare in un route specifico (/chats/new)
    });

    socket.on('chat message', (msg) => {
       // console.log('Message: ' + msg);
        io.emit('chat message', msg);
    });
});

app.post('/chats/new', (req, res) => {
    const btnGroup = req.body.btnGroup;
    const btnSingle = req.body.btnSingle; // valore dei bottoni da recuperare
    const chatName = req.body.nameForm;

    console.log(btnGroup);
    console.log(btnSingle);
    console.log(chatName);

    res.send('Pippo');
});

app.get('/account', (req, res) => {
    if (req.session.user) {
        const username = req.session.user;
        
        pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
            if (error) {
                console.error('[ERROR] Error during query execution:', error);
                res.status(500).send('Server error!');
            } else {
                const email = results.rows[0].email;
                const userid = results.rows[0].userid;
                // console.log(userid)
                const data = { username, email, userid };
                res.render('accountSettings', data);
            }
        });
    } else {
        res.redirect('/account/login');
    }
});

app.get('/account/security', (req, res) => {
    if (req.session.user) {
        const username = req.session.user;
        pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
            if (error) {
                console.error('[ERROR] Error during query execution:', error);
                res.status(500).send('Server error!');                
            } else {
                const two_step = results.rows[0].two_step_verification;
                console.log(two_step);
                const data = { username, two_step }
                res.render('accountSettings-Security', data);
            }
        });
    } else {
        res.redirect('/account/login');
    }
});

app.get('/account/friends', (req, res) => {
    if (req.session.user) {
        const username = req.session.user;

        const data = { username }
        res.render('accountSettings-Friends', data);
    } else {
        res.redirect('/account/login');
    }
});

app.post('/account/actions/delete', (req, res) => {
    const username = req.session.user;

    pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error!');
        } else {
            const user = results.rows[0];
            const password = req.body.password;

            bcrypt.compare(password, user.password, (error, passwordMatch) => {
                if (error) {
                    console.error('Error during credential verify:', error);
                    res.status(500).send('Server error'); 
                }
    
                if (passwordMatch) {
                    if (results.rows.length > 0) {
                        const userid = results.rows[0].userid;

                        pool.query('DELETE FROM users WHERE userid = $1', [userid], (error, results) => {
                            if (error) {
                                res.status(500).send('Server error!');
                                console.error('[ERROR] Error during query execution:', error);
                            } else {
                                res.redirect('/');
                            }
                        });
                    } else {
                        console.log('No user found!')
                        res.status(404).send('User not found');
                    }
                } else {
                    // console.log(results);
                    const errorMessage = true;
                    const message = "Password errata, perfavore riprova!"
                    const data = { errorMessage, message };
                    res.render('accountSettings', data)
                }
            });
        }
    });
});

app.post('/account/actions/changePassword', (req, res) => {
    const actualPassword = req.body.oldPassword;
    const newPassword = req.body.newPassword;
    const confirmNewPassword = req.body.confirmNewPassword;

    const username = req.session.user;

    pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error');            
        } else {
            const user = results.rows[0];
            
            bcrypt.compare(actualPassword, user.password, async (error, passwordMatch) => {
                if (error) {
                    console.error('[ERROR] Error during credentials verify:', error);
                    res.status(500).send('Server error');
                }

                if (passwordMatch) {
                    if (newPassword === confirmNewPassword) {
                        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
                        if (results.rows.length > 0) {
                            const userid = results.rows[0].userid;

                            pool.query('UPDATE users SET password = $1 WHERE userid = $2', [hashedNewPassword, userid], (error, results) => {
                                if (error) {
                                    res.status(500).send('Server error!');
                                    console.error('[ERROR] Error during query execution:', error);
                                } else {
                                    const messageValue = true;
                                    const message = "Password aggiornata con successo!";
                                    const data = { messageValue, message };

                                    res.render('accountSettings-Security', data);
                                }
                            });

                        }
                    } else {
                        const errorMessage = true;
                        const message = "Le due password non corrispondono!";
                        const data = { errorMessage, message };
                        res.render('accountSettings-Security', data);                            
                    }
                } else {
                    const errorMessage = true;
                    const message = "Password errata, perfavore riprova!";
                    const data = { errorMessage, message };
                    res.render('accountSettings-Security', data);                
                }
            });
        }
    });
});

app.post('/account/actions/enable2FA', (req, res) => {
    const password = req.body.password;
    const username = req.session.user;

    pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error');  
        } else {
            const user = results.rows[0];

            bcrypt.compare(password, user.password, (error, passwordMatch) => {
                if (error) {
                    console.error('[ERROR] Error during credentials verify:', error);
                    res.status(500).send('Server error');                    
                }

                if (passwordMatch) {
                    res.redirect('/account/test/autenticazione-a-due-fattori/v1');
                } else {
                    const errorMessage2FA = true;
                    const message = "Password errata, perfavore riprova!";
                    const data = { errorMessage2FA, message };

                    res.render('accountSettings-Security', data);
                }
            });
        }
    });
});

app.post('/account/actions/disable2FA', (req, res) => {
    const password = req.body.password;
    const username = req.session.user;

    pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error');  
        } else {
            const user = results.rows[0];

            bcrypt.compare(password, user.password, (error, passwordMatch) => {
                if (error) {
                    console.error('[ERROR] Error during credentials verify:', error);
                    res.status(500).send('Server error');                    
                }

                if (passwordMatch) {
                    pool.query("UPDATE users SET two_step_verification = 'false' WHERE username = $1", [username], (error, results) => {
                        if (error) {
                            console.error('[ERROR] Error during credentials verify:', error);
                            res.status(500).send('Server error');                            
                        } else {
                            const messageValue2FA = true;
                            const message = "Verifica in due passaggi disattivata."
                            const data = { messageValue2FA, message };
                            res.render('accountSettings-Security', data);
                        }
                    });
                } else {
                    const errorMessage2FA = true;
                    const message = "Password errata, perfavore riprova!";
                    const data = { errorMessage2FA, message };

                    res.render('accountSettings-Security', data);
                }
            });
        }
    });
});

app.get('/account/test/autenticazione-a-due-fattori/v1', (req, res) => {
    res.render('test2FA.hbs');

    const username = req.session.user;

    pool.query('SELECT * FROM users WHERE username = $1', [username], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error');              
        } else {
            const userEmail = results.rows[0].email;

            pool.query('SELECT * FROM login_codes WHERE session = $1', [username], (error, results) => {
                if (error) {
                    console.error('[ERROR] Error during query execution:', error);
                    res.status(500).send('Server error');                     
                }

                if (!results || !results.rows || results.rows.length === 0) {
                    const code = generateCode();
                    saveCode(code, username)
        
                    const emailMessage = createEmailMessage(code);
                
                    const subject = 'Codice di autenticazione';
                    const recipientEmail = userEmail;
                
                    sendEmail(recipientEmail, subject, emailMessage);
                } else {
                    console.log('[2FA System] Codice per sessione', username, 'già esistente');
                }
            });
        }
    });
});

app.post('/account/test/autenticazione-a-due-fattori/v1/endpoint', (req, res) => {                          //FARE IN MODO CHE NON CREI MOLTEPLICI CODICI E FAR FUNZIONARE LA CONVALIDAZIONE DEL CODICE
    const formCode = req.body.code;
    const username = req.session.user;

    pool.query('SELECT * FROM login_codes WHERE session = $1', [username], (error, results) => {
        if (error) {
            console.error('[ERROR] Error during query execution:', error);
            res.status(500).send('Server error');          
        } else {
            const code = results.rows[0].code;

            if (formCode === code) {
                pool.query("UPDATE users SET two_step_verification = 'true' WHERE username = $1", [username], (error, results) => {
                    if (error) {
                        console.error('[ERROR] Error during query execution:', error);
                        res.status(500).send('Server error');                       
                    } else {
                        console.log('[2FA System] Attivata verifica in due passaggi per', username);
                        const messageValue2FA = true;
                        const message = "Verifica in due passaggi attivata!";
                        const data = { messageValue2FA, message };
                
                        res.render('accountSettings-Security', data);  
                    }
                });
            } else {
                console.log('[2FA System] Errore durante l\'attivazione della verifica in due passaggi')
                const errorMessage = true;
                const message = "Il codice inserito è errato!";
                const data = { errorMessage, message };
        
                res.render('test2FA', data);
            }
        }
    });
});

app.get('/account/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/account/login');
});

// app.get('/testing', (req, res) => {
//   res.render('2falogin');
// });

app.get('/policies/termini-di-servizio2023', (req, res) => {
    res.sendFile(__dirname + '/assets/templates/tds2023.html');
});

server.listen(8080, '10.0.0.109',() => {
    console.log('[INFO] Server running on port 8080');
});
