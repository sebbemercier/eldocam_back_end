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

// --- Rate Limiting (protection anti-spam) ---
var (
	rateLimitMutex sync.Mutex
	rateLimits     = make(map[string][]time.Time)
	urlRegex       = regexp.MustCompile(`https?://[\w\.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+`)
)

// Structure du formulaire avec validation
type ContactForm struct {
	Name     string `json:"name" validate:"required,min=2,max=80"`
	Email    string `json:"email" validate:"required,email"`
	Tel      string `json:"tel" validate:"max=40"`
	Language string `json:"language"`
	Message  string `json:"message" validate:"required,min=3,max=5000"`
}

// --- Health Check Handler (pour Kubernetes) ---
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// --- Fonction de rate limiting (max 3 requêtes par IP toutes les 10 min) ---
func isRateLimited(ip string) bool {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	windowStart := now.Add(-10 * time.Minute)

	// Nettoyer les anciennes entrées
	var validTimes []time.Time
	for _, t := range rateLimits[ip] {
		if t.After(windowStart) {
			validTimes = append(validTimes, t)
		}
	}
	rateLimits[ip] = validTimes

	// Vérifier la limite
	if len(rateLimits[ip]) >= 3 {
		log.Printf("⚠️ Rate limit dépassé pour %s (%d requêtes)", ip, len(rateLimits[ip]))
		return true
	}

	// Ajouter la nouvelle requête
	rateLimits[ip] = append(rateLimits[ip], now)
	return false
}

// --- Détection de spam basique ---
func containsSpam(message string) bool {
	lowerMsg := strings.ToLower(message)

	// Détection d'URLs (potentiellement du spam)
	if urlRegex.MatchString(message) {
		log.Println("⚠️ URL détectée dans le message")
		return true
	}

	// Mots-clés spam courants
	spamKeywords := []string{
		"viagra", "casino", "lottery", "prize", "click here",
		"buy now", "limited offer", "crypto", "investment",
		"bitcoin", "free money", "earn money", "work from home",
	}

	for _, keyword := range spamKeywords {
		if strings.Contains(lowerMsg, keyword) {
			log.Printf("⚠️ Mot-clé spam détecté: %s", keyword)
			return true
		}
	}

	return false
}

// --- Validation email robuste ---
func isValidEmail(email string) bool {
	// Regex email standard RFC 5322
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	if !emailRegex.MatchString(email) {
		return false
	}

	// Bloquer les domaines jetables courants
	disposableDomains := []string{
		"tempmail.com", "guerrillamail.com", "10minutemail.com",
		"mailinator.com", "throwaway.email", "yopmail.com",
	}

	emailLower := strings.ToLower(email)
	for _, domain := range disposableDomains {
		if strings.HasSuffix(emailLower, "@"+domain) {
			log.Printf("⚠️ Email jetable détecté: %s", email)
			return false
		}
	}

	return true
}

// --- Vérification Cloudflare Turnstile ---
func verifyTurnstile(token, ip string) bool {
	secret := os.Getenv("TURNSTILE_SECRET")
	if secret == "" {
		log.Println("❌ TURNSTILE_SECRET non configuré")
		return false
	}

	payload := fmt.Sprintf(`{"secret":"%s","response":"%s","remoteip":"%s"}`, secret, token, ip)
	resp, err := http.Post(
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		"application/json",
		strings.NewReader(payload),
	)
	if err != nil {
		log.Println("❌ Erreur requête Turnstile:", err)
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Println("❌ Erreur parsing Turnstile:", err)
		return false
	}

	success, ok := result["success"].(bool)
	if !ok || !success {
		log.Println("❌ Vérification Turnstile échouée:", result)
	}
	return ok && success
}

// --- Handler pour le formulaire de contact ---
func contactHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Récupération de l'IP réelle
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}

	log.Printf("📩 Nouvelle requête de contact depuis %s", ip)

	// 🔒 Rate limiting
	if isRateLimited(ip) {
		log.Printf("🚫 Trop de requêtes depuis %s", ip)
		http.Error(w, "Trop de requêtes. Veuillez réessayer plus tard.", http.StatusTooManyRequests)
		return
	}

	// Détecter le Content-Type
	contentType := r.Header.Get("Content-Type")
	log.Printf("📋 Content-Type: %s", contentType)

	var form ContactForm
	var turnstileToken string

	if strings.Contains(contentType, "application/json") {
		// Format JSON
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println("❌ Erreur lecture body:", err)
			http.Error(w, "Erreur de lecture des données", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		type RequestWithToken struct {
			Name           string `json:"name"`
			Email          string `json:"email"`
			Tel            string `json:"tel"`
			Language       string `json:"language"`
			Message        string `json:"message"`
			TurnstileToken string `json:"cf-turnstile-response"`
		}

		var requestData RequestWithToken
		if err := json.Unmarshal(body, &requestData); err != nil {
			log.Println("❌ Erreur décodage JSON:", err)
			http.Error(w, "Données JSON invalides", http.StatusBadRequest)
			return
		}

		form = ContactForm{
			Name:     requestData.Name,
			Email:    requestData.Email,
			Tel:      requestData.Tel,
			Language: requestData.Language,
			Message:  requestData.Message,
		}
		turnstileToken = requestData.TurnstileToken

	} else {
		// Format application/x-www-form-urlencoded
		if err := r.ParseForm(); err != nil {
			log.Println("❌ Erreur parsing formulaire:", err)
			http.Error(w, "Erreur de parsing", http.StatusBadRequest)
			return
		}

		form = ContactForm{
			Name:     r.FormValue("name"),
			Email:    r.FormValue("email"),
			Tel:      r.FormValue("tel"),
			Language: r.FormValue("language"),
			Message:  r.FormValue("message"),
		}
		turnstileToken = r.FormValue("cf-turnstile-response")
	}

	// 🔒 Vérification Turnstile OBLIGATOIRE
	if turnstileToken == "" {
		log.Println("❌ Token Turnstile manquant")
		http.Error(w, "Vérification de sécurité manquante.", http.StatusBadRequest)
		return
	}

	if !verifyTurnstile(turnstileToken, ip) {
		log.Println("❌ Vérification Turnstile échouée")
		http.Error(w, "Vérification de sécurité échouée.", http.StatusBadRequest)
		return
	}

	log.Println("✅ Vérification Turnstile réussie")

	// Nettoyage et validation des champs
	form.Name = strings.TrimSpace(form.Name)
	form.Email = strings.TrimSpace(strings.ToLower(form.Email))
	form.Tel = strings.TrimSpace(form.Tel)
	form.Message = strings.TrimSpace(form.Message)

	if form.Name == "" || len(form.Name) < 2 || len(form.Name) > 80 {
		log.Println("❌ Nom invalide")
		http.Error(w, "Le nom doit contenir entre 2 et 80 caractères", http.StatusBadRequest)
		return
	}

	if !isValidEmail(form.Email) {
		log.Println("❌ Email invalide:", form.Email)
		http.Error(w, "Email invalide", http.StatusBadRequest)
		return
	}

	if len(form.Tel) > 40 {
		log.Println("❌ Téléphone trop long")
		http.Error(w, "Numéro de téléphone trop long", http.StatusBadRequest)
		return
	}

	if form.Message == "" || len(form.Message) < 3 || len(form.Message) > 5000 {
		log.Println("❌ Message invalide (longueur)")
		http.Error(w, "Le message doit contenir entre 3 et 5000 caractères", http.StatusBadRequest)
		return
	}

	// 🔒 Détection de spam
	if containsSpam(form.Message) {
		log.Printf("🚫 Spam détecté depuis %s", ip)
		http.Error(w, "Message non autorisé", http.StatusForbidden)
		return
	}

	log.Printf("✅ Formulaire valide de %s (%s)", form.Name, form.Email)

	// Envoi de l'email
	mailjetAPIKey := os.Getenv("MAILJET_API_KEY")
	mailjetSecretKey := os.Getenv("MAILJET_SECRET_KEY")
	senderEmail := os.Getenv("SENDER_EMAIL")
	senderName := os.Getenv("SENDER_NAME")
	adminTo := os.Getenv("ADMIN_TO")

	if mailjetAPIKey == "" || mailjetSecretKey == "" || senderEmail == "" || adminTo == "" {
		log.Println("❌ Variables d'environnement manquantes")
		http.Error(w, "Configuration serveur incomplète", http.StatusInternalServerError)
		return
	}

	successMsg, err := sendEmail(form, mailjetAPIKey, mailjetSecretKey, senderEmail, senderName, adminTo)
	if err != nil {
		log.Println("❌ Erreur lors de l'envoi:", err)
		http.Error(w, "Erreur lors de l'envoi du message", http.StatusInternalServerError)
		return
	}

	// Réponse JSON avec message traduit
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": successMsg,
	})
}

// --- Envoi d'email via Mailjet ---
func sendEmail(form ContactForm, mailjetAPIKey, mailjetSecretKey, senderEmail, senderName, adminTo string) (string, error) {
	mailjetClient := mailjet.NewMailjetClient(mailjetAPIKey, mailjetSecretKey)

	// Échapper les caractères HTML
	escapedName := html.EscapeString(form.Name)
	escapedEmail := html.EscapeString(form.Email)
	escapedTel := html.EscapeString(form.Tel)
	escapedMessage := html.EscapeString(form.Message)

	// Email pour l'admin
	adminSubject := fmt.Sprintf("📩 Nouveau message de %s", escapedName)
	adminHTMLBody := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nouveau message</title>
</head>
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background-color: #f4f4f4; padding: 20px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">
                                📩 Nouveau Message
                            </h1>
                        </td>
                    </tr>

                    <!-- Content -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            <h2 style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 20px;">
                                Informations du contact
                            </h2>
                            
                            <table role="presentation" width="100%%" cellspacing="0" cellpadding="10" style="margin-bottom: 20px;">
                                <tr style="background-color: #f9fafb;">
                                    <td style="padding: 12px; font-weight: bold; color: #374151; border-bottom: 1px solid #e5e7eb;">
                                        Nom :
                                    </td>
                                    <td style="padding: 12px; color: #1a1a1a; border-bottom: 1px solid #e5e7eb;">
                                        %s
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 12px; font-weight: bold; color: #374151; border-bottom: 1px solid #e5e7eb;">
                                        Email :
                                    </td>
                                    <td style="padding: 12px; border-bottom: 1px solid #e5e7eb;">
                                        <a href="mailto:%s" style="color: #dc2626; text-decoration: none;">%s</a>
                                    </td>
                                </tr>
                                <tr style="background-color: #f9fafb;">
                                    <td style="padding: 12px; font-weight: bold; color: #374151; border-bottom: 1px solid #e5e7eb;">
                                        Téléphone :
                                    </td>
                                    <td style="padding: 12px; color: #1a1a1a; border-bottom: 1px solid #e5e7eb;">
                                        %s
                                    </td>
                                </tr>
                            </table>

                            <h2 style="margin: 30px 0 15px 0; color: #1a1a1a; font-size: 20px;">
                                Message
                            </h2>
                            <div style="background-color: #f9fafb; border-left: 4px solid #dc2626; padding: 20px; border-radius: 4px;">
                                <p style="margin: 0; color: #1a1a1a; font-size: 16px; line-height: 1.6; white-space: pre-wrap;">%s</p>
                            </div>
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #1a1a1a; padding: 20px; text-align: center;">
                            <p style="margin: 0; color: #ffffff; font-size: 14px;">
                                <strong style="color: #dc2626;">Eldocam</strong> - Système de contact automatisé
                            </p>
                            <p style="margin: 5px 0 0 0; color: #999; font-size: 12px;">
                                Envoyé le %s
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    `, escapedName, escapedEmail, escapedEmail, escapedTel, escapedMessage, time.Now().Format("02/01/2006 à 15:04"))

	adminMessage := mailjet.InfoMessagesV31{
		From: &mailjet.RecipientV31{
			Email: senderEmail,
			Name:  senderName,
		},
		To: &mailjet.RecipientsV31{
			mailjet.RecipientV31{
				Email: adminTo,
			},
		},
		Subject:  adminSubject,
		HTMLPart: adminHTMLBody,
	}

	// Email de confirmation pour le client
	var confirmSubject, confirmTextBody, confirmHTMLBody string

	switch strings.ToLower(form.Language) {
	case "en":
		confirmSubject = "✅ Message Received - Eldocam"
		confirmTextBody = fmt.Sprintf("Hello %s,\n\nThank you for contacting us. We have received your message and will respond as soon as possible.\n\nBest regards,\nThe Eldocam Team", escapedName)
		confirmHTMLBody = fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background-color: #f4f4f4; padding: 20px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">✅ Message Received</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 15px 0; color: #1a1a1a; font-size: 18px;">
                                Hello <strong style="color: #dc2626;">%s</strong>,
                            </p>
                            <p style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Thank you for contacting us. We have received your message and will respond as soon as possible.
                            </p>
                            <p style="margin: 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Best regards,<br>
                                <strong style="color: #dc2626;">The Eldocam Team</strong>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #1a1a1a; padding: 20px; text-align: center;">
                            <p style="margin: 5px 0 0 0; color: #999; font-size: 12px;">
                                This is an automated message, please do not reply.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
        `, escapedName)

	case "nl":
		confirmSubject = "✅ Bericht Ontvangen - Eldocam"
		confirmTextBody = fmt.Sprintf("Hallo %s,\n\nBedankt voor uw contact. We hebben uw bericht ontvangen en zullen zo snel mogelijk reageren.\n\nMet vriendelijke groet,\nHet Eldocam Team", escapedName)
		confirmHTMLBody = fmt.Sprintf(`
<!DOCTYPE html>
<html lang="nl">
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background-color: #f4f4f4; padding: 20px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">✅ Bericht Ontvangen</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 15px 0; color: #1a1a1a; font-size: 18px;">
                                Hallo <strong style="color: #dc2626;">%s</strong>,
                            </p>
                            <p style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Bedankt voor uw contact. We hebben uw bericht ontvangen en zullen zo snel mogelijk reageren.
                            </p>
                            <p style="margin: 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Met vriendelijke groet,<br>
                                <strong style="color: #dc2626;">Het Eldocam Team</strong>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #1a1a1a; padding: 20px; text-align: center;">
                            <p style="margin: 5px 0 0 0; color: #999; font-size: 12px;">
                                Dit is een geautomatiseerd bericht, gelieve niet te antwoorden.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
        `, escapedName)

	default:
		confirmSubject = "✅ Message Reçu - Eldocam"
		confirmTextBody = fmt.Sprintf("Bonjour %s,\n\nMerci de nous avoir contactés. Nous avons bien reçu votre message et vous répondrons dans les plus brefs délais.\n\nCordialement,\nL'équipe Eldocam", escapedName)
		confirmHTMLBody = fmt.Sprintf(`
<!DOCTYPE html>
<html lang="fr">
<body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background-color: #f4f4f4; padding: 20px 0;">
        <tr>
            <td align="center">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">✅ Message Reçu</h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 15px 0; color: #1a1a1a; font-size: 18px;">
                                Bonjour <strong style="color: #dc2626;">%s</strong>,
                            </p>
                            <p style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Merci de nous avoir contactés. Nous avons bien reçu votre message et nous vous répondrons dans les plus brefs délais.
                            </p>
                            <p style="margin: 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Cordialement,<br>
                                <strong style="color: #dc2626;">L'équipe Eldocam</strong>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #1a1a1a; padding: 20px; text-align: center;">
                            <p style="margin: 5px 0 0 0; color: #999; font-size: 12px;">
                                Ceci est un message automatique, merci de ne pas y répondre.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
        `, escapedName)
	}

	confirmMessage := mailjet.InfoMessagesV31{
		From: &mailjet.RecipientV31{
			Email: senderEmail,
			Name:  senderName,
		},
		To: &mailjet.RecipientsV31{
			mailjet.RecipientV31{
				Email: form.Email,
				Name:  form.Name,
			},
		},
		Subject:  confirmSubject,
		TextPart: confirmTextBody,
		HTMLPart: confirmHTMLBody,
	}

	// Envoi des deux emails
	messages := mailjet.MessagesV31{
		Info: []mailjet.InfoMessagesV31{adminMessage, confirmMessage},
	}

	res, err := mailjetClient.SendMailV31(&messages)
	if err != nil {
		return "", fmt.Errorf("erreur Mailjet: %w", err)
	}

	if len(res.ResultsV31) > 0 {
		firstResult := res.ResultsV31[0]
		if firstResult.Status != "success" {
			return "", fmt.Errorf("échec envoi email: statut=%s", firstResult.Status)
		}
	}

	log.Printf("✅ Emails envoyés avec succès à %s et %s", adminTo, form.Email)

	switch strings.ToLower(form.Language) {
	case "en":
		return "Message sent successfully!", nil
	case "nl":
		return "Bericht succesvol verzonden!", nil
	default:
		return "Message envoyé avec succès !", nil
	}
}

func main() {
	// Charger le fichier .env (optionnel en production K8s)
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ Aucun fichier .env trouvé, utilisation des variables système")
	}

	// Vérifier les variables d'environnement critiques
	requiredVars := []string{
		"MAILJET_API_KEY",
		"MAILJET_SECRET_KEY",
		"SENDER_EMAIL",
		"ADMIN_TO",
		"TURNSTILE_SECRET",
	}

	for _, v := range requiredVars {
		if os.Getenv(v) == "" {
			log.Fatalf("❌ Variable d'environnement manquante: %s", v)
		}
	}

	log.Println("✅ Configuration chargée avec succès")

	// Configuration CORS sécurisée
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{
			"https://eldocam.com",
			"https://eldocam.be",
			"https://www.eldocam.com",
			"https://www.eldocam.be",
			"http://localhost:3000",
		},
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-Requested-With"},
		AllowCredentials: false,
		MaxAge:           3600,
	})

	// Enregistrer les routes
	http.HandleFunc("/health", healthHandler)
	http.Handle("/", corsHandler.Handler(http.HandlerFunc(contactHandler)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	log.Printf("🚀 Serveur démarré sur le port %s", port)
	log.Printf("🔒 Rate limiting: 3 requêtes max par IP / 10 minutes")
	log.Printf("🛡️ Cloudflare Turnstile: Activé")
	log.Printf("🚫 Détection de spam: Activée")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("❌ Erreur serveur:", err)
	}
}
