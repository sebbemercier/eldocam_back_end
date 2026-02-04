package main

import (
    "encoding/json"
    "fmt"
    "html"
    "io"
    "log"
    "net/http"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/joho/godotenv"
    "github.com/mailjet/mailjet-apiv3-go/v4"
    "github.com/rs/cors"
)

// Configuration globale
type Config struct {
    MailjetAPIKey    string
    MailjetSecretKey string
    SenderEmail      string
    SenderName       string
    AdminTo          string
    TurnstileSecret  string
}

var config Config

// Structure du formulaire de contact
type ContactForm struct {
    Name     string `json:"name"`
    Email    string `json:"email"`
    Tel      string `json:"tel"`
    Message  string `json:"message"`
    Language string `json:"language"`
}

// Rate limiting simple (en mémoire)
type RateLimiter struct {
    mu      sync.Mutex
    clients map[string][]time.Time
}

var limiter = &RateLimiter{
    clients: make(map[string][]time.Time),
}

const (
    maxRequests = 3
    timeWindow  = 10 * time.Minute
)

// Fonction pour parser les deux formats (JSON et form-urlencoded)
func parseContactForm(r *http.Request) (*ContactForm, error) {
    var form ContactForm

    contentType := r.Header.Get("Content-Type")

    if strings.Contains(contentType, "application/json") {
        // Format JSON
        if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
            return nil, fmt.Errorf("format JSON invalide: %w", err)
        }
    } else if strings.Contains(contentType, "application/x-www-form-urlencoded") || r.Method == "POST" {
        // Format formulaire classique
        if err := r.ParseForm(); err != nil {
            return nil, fmt.Errorf("erreur parsing formulaire: %w", err)
        }

        form = ContactForm{
            Name:     r.FormValue("name"),
            Email:    r.FormValue("email"),
            Tel:      r.FormValue("tel"),
            Message:  r.FormValue("message"),
            Language: r.FormValue("language"),
        }
    } else {
        return nil, fmt.Errorf("content-type non supporté: %s", contentType)
    }

    return &form, nil
}

// Fonction de rate limiting
func isRateLimited(clientIP string) bool {
    limiter.mu.Lock()
    defer limiter.mu.Unlock()

    now := time.Now()
    cutoff := now.Add(-timeWindow)

    // Nettoyer les anciennes entrées
    if times, exists := limiter.clients[clientIP]; exists {
        var validTimes []time.Time
        for _, t := range times {
            if t.After(cutoff) {
                validTimes = append(validTimes, t)
            }
        }
        limiter.clients[clientIP] = validTimes

        if len(validTimes) >= maxRequests {
            return true
        }
    }

    // Ajouter la nouvelle requête
    limiter.clients[clientIP] = append(limiter.clients[clientIP], now)
    return false
}

// Vérification Cloudflare Turnstile
func verifyTurnstile(token, clientIP string) bool {
    if config.TurnstileSecret == "" {
        log.Println("⚠️ TURNSTILE_SECRET non configuré, validation ignorée")
        return true
    }

    data := fmt.Sprintf(`{"secret":"%s","response":"%s","remoteip":"%s"}`,
        config.TurnstileSecret, token, clientIP)

    resp, err := http.Post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        "application/json",
        strings.NewReader(data),
    )
    if err != nil {
        log.Printf("❌ Erreur vérification Turnstile: %v", err)
        return false
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    var result map[string]interface{}
    json.Unmarshal(body, &result)

    success, _ := result["success"].(bool)
    return success
}

// Détection basique de spam
func containsSpam(message string) bool {
    spamPatterns := []string{
        `(?i)viagra`,
        `(?i)casino`,
        `(?i)lottery`,
        `(?i)prince`,
        `(?i)inheritance`,
        `(?i)click here`,
        `(?i)buy now`,
        `http[s]?://[^\s]{50,}`, // URLs très longues
    }

    for _, pattern := range spamPatterns {
        matched, _ := regexp.MatchString(pattern, message)
        if matched {
            return true
        }
    }
    return false
}

// Messages traduits
func getTranslatedMessage(language string) (subject string, greeting string, body string, closing string) {
    switch language {
    case "en":
        return "Thank you for contacting Eldocam",
            "Hello",
            "Thank you for contacting us. We have received your message and will get back to you as soon as possible.",
            "Best regards,\nThe Eldocam Team"
    case "nl":
        return "Bedankt voor het contacteren van Eldocam",
            "Hallo",
            "Bedankt voor uw bericht. We hebben uw bericht ontvangen en zullen zo snel mogelijk contact met u opnemen.",
            "Met vriendelijke groet,\nHet Eldocam Team"
    default: // "fr"
        return "Merci d'avoir contacté Eldocam",
            "Bonjour",
            "Merci de nous avoir contactés. Nous avons bien reçu votre message et nous vous répondrons dans les plus brefs délais.",
            "Cordialement,\nL'équipe Eldocam"
    }
}

// Envoi de l'email via Mailjet
func sendEmail(form *ContactForm) (string, error) {
    mailjetClient := mailjet.NewMailjetClient(config.MailjetAPIKey, config.MailjetSecretKey)

    // Échapper les données HTML
    safeName := html.EscapeString(form.Name)
    safeEmail := html.EscapeString(form.Email)
    safeTel := html.EscapeString(form.Tel)
    safeMessage := html.EscapeString(form.Message)

    // Email pour l'admin
    adminHTMLContent := fmt.Sprintf(`
        <h2>Nouveau message de contact - Eldocam</h2>
        <p><strong>Nom :</strong> %s</p>
        <p><strong>Email :</strong> %s</p>
        <p><strong>Téléphone :</strong> %s</p>
        <p><strong>Message :</strong></p>
        <p>%s</p>
    `, safeName, safeEmail, safeTel, strings.ReplaceAll(safeMessage, "\n", "<br>"))

    adminTextContent := fmt.Sprintf(
        "Nouveau message de contact\n\nNom: %s\nEmail: %s\nTéléphone: %s\n\nMessage:\n%s",
        safeName, safeEmail, safeTel, safeMessage,
    )

    messagesInfo := []mailjet.InfoMessagesV31{
        {
            From: &mailjet.RecipientV31{
                Email: config.SenderEmail,
                Name:  config.SenderName,
            },
            To: &mailjet.RecipientsV31{
                mailjet.RecipientV31{
                    Email: config.AdminTo,
                },
            },
            Subject:  "Nouveau message de contact - Eldocam",
            TextPart: adminTextContent,
            HTMLPart: adminHTMLContent,
        },
    }

    // Auto-reply au client
    subject, greeting, body, closing := getTranslatedMessage(form.Language)

    clientHTMLContent := fmt.Sprintf(`
        <h2>%s</h2>
        <p>%s %s,</p>
        <p>%s</p>
        <hr>
        <p><strong>Votre message :</strong></p>
        <p>%s</p>
        <hr>
        <p>%s</p>
    `, subject, greeting, safeName, body, strings.ReplaceAll(safeMessage, "\n", "<br>"), closing)

    clientTextContent := fmt.Sprintf(
        "%s %s,\n\n%s\n\n---\nVotre message:\n%s\n\n---\n%s",
        greeting, safeName, body, safeMessage, closing,
    )

    messagesInfo = append(messagesInfo, mailjet.InfoMessagesV31{
        From: &mailjet.RecipientV31{
            Email: config.SenderEmail,
            Name:  config.SenderName,
        },
        To: &mailjet.RecipientsV31{
            mailjet.RecipientV31{
                Email: form.Email,
                Name:  form.Name,
            },
        },
        Subject:  subject,
        TextPart: clientTextContent,
        HTMLPart: clientHTMLContent,
    })

    messages := mailjet.MessagesV31{Info: messagesInfo}
    res, err := mailjetClient.SendMailV31(&messages)
    if err != nil {
        return "", fmt.Errorf("erreur Mailjet: %w", err)
    }

    if res.ResultsV31[0].Status != "success" {
        return "", fmt.Errorf("échec envoi email: %s", res.ResultsV31[0].Status)
    }

    log.Printf("✅ Email envoyé avec succès à %s et %s", config.AdminTo, form.Email)
    return "Message envoyé avec succès !", nil
}

// Handler pour le formulaire de contact
func contactHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")

    // ✅ Accepte POST et OPTIONS
    if r.Method == "OPTIONS" {
        w.WriteHeader(http.StatusOK)
        return
    }

    if r.Method != "POST" {
        w.WriteHeader(http.StatusMethodNotAllowed)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Méthode non autorisée. Utilisez POST.",
        })
        return
    }

    // Rate limiting
    clientIP := r.RemoteAddr
    if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
        clientIP = strings.Split(forwarded, ",")[0]
    }

    if isRateLimited(clientIP) {
        log.Printf("⚠️ Rate limit dépassé pour %s", clientIP)
        w.WriteHeader(http.StatusTooManyRequests)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Trop de requêtes. Veuillez réessayer dans 10 minutes.",
        })
        return
    }

    // ✅ Parse le formulaire (JSON ou form-urlencoded)
    form, err := parseContactForm(r)
    if err != nil {
        log.Printf("❌ Erreur parsing: %v", err)
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": err.Error(),
        })
        return
    }

    // Validation basique
    if form.Name == "" || form.Email == "" || form.Message == "" {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Veuillez remplir tous les champs obligatoires",
        })
        return
    }

    // Validation email
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(form.Email) {
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Format d'email invalide",
        })
        return
    }

    // Détection de spam
    if containsSpam(form.Message) {
        log.Printf("⚠️ Spam détecté de %s", clientIP)
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Message rejeté (contenu suspect détecté)",
        })
        return
    }

    // Vérification Turnstile
    turnstileToken := r.FormValue("cf-turnstile-response")
    if turnstileToken == "" {
        // Essayer de le récupérer du JSON si présent
        var jsonData map[string]string
        r.Body = io.NopCloser(strings.NewReader("")) // Reset body
        if err := json.NewDecoder(r.Body).Decode(&jsonData); err == nil {
            turnstileToken = jsonData["cf-turnstile-response"]
        }
    }

    if turnstileToken == "" {
        log.Printf("⚠️ Token Turnstile manquant de %s", clientIP)
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Vérification anti-robot manquante",
        })
        return
    }

    if !verifyTurnstile(turnstileToken, clientIP) {
        log.Printf("❌ Échec vérification Turnstile pour %s", clientIP)
        w.WriteHeader(http.StatusForbidden)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Échec de la vérification anti-robot",
        })
        return
    }

    // Envoi de l'email
    message, err := sendEmail(form)
    if err != nil {
        log.Printf("❌ Erreur envoi email: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Erreur lors de l'envoi de l'email",
        })
        return
    }

    // Succès
    log.Printf("✅ Message envoyé avec succès de %s (%s)", form.Name, form.Email)
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "success": "true",
        "message": message,
    })
}

// Handler pour la page d'accueil
func homeHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    html := `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Eldocam API</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            h1 { color: #333; }
            .endpoint { background: #f4f4f4; padding: 15px; margin: 10px 0; border-radius: 5px; }
            code { background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>🚀 Eldocam Backend API</h1>
        <p>Bienvenue sur l'API Eldocam</p>
        
        <div class="endpoint">
            <h2>GET /health</h2>
            <p>Vérifie l'état du serveur</p>
        </div>
        
        <div class="endpoint">
            <h2>POST /api/contact</h2>
            <p>Envoie un message de contact</p>
            <p><strong>Formats acceptés :</strong> <code>application/json</code> ou <code>application/x-www-form-urlencoded</code></p>
            <p><strong>Champs requis :</strong> name, email, tel, message, language, cf-turnstile-response</p>
        </div>
    </body>
    </html>
    `
    w.Write([]byte(html))
}

// Handler pour le health check
func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status":    "healthy",
        "timestamp": time.Now().Format(time.RFC3339),
        "service":   "eldocam-backend",
        "version":   "1.0.0",
    })
}

// Chargement de la configuration
func loadConfig() error {
    // Charger .env si présent
    godotenv.Load()

    config = Config{
        MailjetAPIKey:    os.Getenv("MAILJET_API_KEY"),
        MailjetSecretKey: os.Getenv("MAILJET_SECRET_KEY"),
        SenderEmail:      os.Getenv("SENDER_EMAIL"),
        SenderName:       os.Getenv("SENDER_NAME"),
        AdminTo:          os.Getenv("ADMIN_TO"),
        TurnstileSecret:  os.Getenv("TURNSTILE_SECRET"),
    }

    // Valeurs par défaut
    if config.SenderEmail == "" {
        config.SenderEmail = "noreply@eldocam.com"
    }
    if config.SenderName == "" {
        config.SenderName = "Eldocam Contact"
    }
    if config.AdminTo == "" {
        config.AdminTo = "smercier2000@gmail.com"
    }

    // Vérifications
    if config.MailjetAPIKey == "" || config.MailjetSecretKey == "" {
        return fmt.Errorf("❌ MAILJET_API_KEY et MAILJET_SECRET_KEY sont requis")
    }

    log.Println("✅ Configuration chargée avec succès")
    return nil
}

func main() {
    // Chargement de la config
    if err := loadConfig(); err != nil {
        log.Fatal(err)
    }

    // Configuration CORS
    c := cors.New(cors.Options{
        AllowedOrigins:   []string{"https://eldocam.com", "https://www.eldocam.com", "http://localhost:3000"},
        AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
        AllowedHeaders:   []string{"Content-Type", "Authorization"},
        AllowCredentials: true,
        MaxAge:           300,
    })

    // Routes
    mux := http.NewServeMux()
    mux.HandleFunc("/", homeHandler)
    mux.HandleFunc("/health", healthHandler)
    mux.HandleFunc("/api/contact", contactHandler)

    // Application du CORS
    handler := c.Handler(mux)

    // Démarrage du serveur
    port := os.Getenv("PORT")
    if port == "" {
        port = "8000"
    }

    log.Printf("🚀 Serveur démarré sur le port %s", port)
    log.Println("📍 Routes actives:")
    log.Println("   GET  /health")
    log.Println("   POST /api/contact")
    log.Println("   GET  /")
    log.Printf("🔒 Rate limiting: %d requêtes max par IP / %v", maxRequests, timeWindow)
    log.Println("🛡️ Cloudflare Turnstile: Activé")
    log.Println("🚫 Détection de spam: Activée")

    if err := http.ListenAndServe(":"+port, handler); err != nil {
        log.Fatal("❌ Erreur serveur:", err)
    }
}
