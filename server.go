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

// --- Root Handler (documentation) ---
func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"service": "Eldocam Backend API",
		"version": "1.0.0",
		"status":  "operational",
		"endpoints": map[string]string{
			"health":  "GET /health",
			"contact": "POST /api/contact",
		},
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
		log.Println("❌ Vérification Turnstile échouée")
		return false
	}

	log.Println("✅ Vérification Turnstile réussie")
	return true
}

// --- Handler principal du formulaire de contact ---
func contactHandler(w http.ResponseWriter, r *http.Request) {
	// Accepter uniquement POST
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"Méthode non autorisée"}`, http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting par IP
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}

	if isRateLimited(ip) {
		log.Printf("🚫 Rate limit pour IP: %s", ip)
		http.Error(w, `{"error":"Trop de requêtes. Réessayez plus tard."}`, http.StatusTooManyRequests)
		return
	}

	// Parser le JSON
	var form ContactForm
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		log.Println("❌ Erreur parsing JSON:", err)
		http.Error(w, `{"error":"Format JSON invalide"}`, http.StatusBadRequest)
		return
	}

	// Validation des champs
	if len(form.Name) < 2 || len(form.Name) > 80 {
		http.Error(w, `{"error":"Le nom doit contenir entre 2 et 80 caractères"}`, http.StatusBadRequest)
		return
	}

	if !isValidEmail(form.Email) {
		http.Error(w, `{"error":"Adresse email invalide"}`, http.StatusBadRequest)
		return
	}

	if len(form.Message) < 3 || len(form.Message) > 5000 {
		http.Error(w, `{"error":"Le message doit contenir entre 3 et 5000 caractères"}`, http.StatusBadRequest)
		return
	}

	// Détection de spam
	if containsSpam(form.Message) {
		log.Println("🚫 Message suspect détecté")
		http.Error(w, `{"error":"Message suspect détecté"}`, http.StatusBadRequest)
		return
	}

	// Vérification Cloudflare Turnstile
	turnstileToken := r.Header.Get("cf-turnstile-response")
	if turnstileToken == "" {
		// Essayer de récupérer depuis le body JSON
		var tokenPayload struct {
			TurnstileToken string `json:"cf-turnstile-response"`
		}
		// Re-parse le body (déjà consommé, donc on utilise une copie)
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &tokenPayload)
		turnstileToken = tokenPayload.TurnstileToken
	}

	if !verifyTurnstile(turnstileToken, ip) {
		log.Println("🚫 Échec vérification Turnstile")
		http.Error(w, `{"error":"Vérification de sécurité échouée"}`, http.StatusForbidden)
		return
	}

	// Envoi des emails
	message, err := sendEmails(form)
	if err != nil {
		log.Println("❌ Erreur envoi email:", err)
		http.Error(w, `{"error":"Erreur lors de l'envoi"}`, http.StatusInternalServerError)
		return
	}

	// Réponse succès
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": message,
	})

	log.Printf("✅ Contact traité avec succès: %s <%s>", form.Name, form.Email)
}

// --- Envoi des emails via Mailjet ---
func sendEmails(form ContactForm) (string, error) {
	apiKey := os.Getenv("MAILJET_API_KEY")
	secretKey := os.Getenv("MAILJET_SECRET_KEY")
	senderEmail := os.Getenv("SENDER_EMAIL")
	senderName := os.Getenv("SENDER_NAME")
	adminTo := os.Getenv("ADMIN_TO")

	if senderName == "" {
		senderName = "Eldocam Contact Form"
	}

	mailjetClient := mailjet.NewMailjetClient(apiKey, secretKey)

	// Échapper les caractères HTML
	escapedName := html.EscapeString(form.Name)
	escapedEmail := html.EscapeString(form.Email)
	escapedTel := html.EscapeString(form.Tel)
	escapedMessage := html.EscapeString(form.Message)

	// Email pour l'admin
	adminSubject := fmt.Sprintf("Nouveau contact depuis eldocam.com - %s", escapedName)
	adminTextBody := fmt.Sprintf(`
Nouveau message de contact reçu :

Nom : %s
Email : %s
Téléphone : %s
Langue : %s

Message :
%s
`, escapedName, escapedEmail, escapedTel, form.Language, escapedMessage)

	adminHTMLBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;">
                                📧 Nouveau Contact
                            </h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <table role="presentation" style="width: 100%%; border-collapse: collapse;">
                                <tr>
                                    <td style="padding: 15px; background-color: #f9fafb; border-left: 4px solid #dc2626; margin-bottom: 15px;">
                                        <p style="margin: 0 0 8px 0; color: #6b7280; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">
                                            👤 Nom
                                        </p>
                                        <p style="margin: 0; color: #1a1a1a; font-size: 16px; font-weight: 600;">
                                            %s
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="height: 15px;"></td>
                                </tr>
                                <tr>
                                    <td style="padding: 15px; background-color: #f9fafb; border-left: 4px solid #dc2626; margin-bottom: 15px;">
                                        <p style="margin: 0 0 8px 0; color: #6b7280; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">
                                            ✉️ Email
                                        </p>
                                        <p style="margin: 0; color: #1a1a1a; font-size: 16px; font-weight: 600;">
                                            <a href="mailto:%s" style="color: #dc2626; text-decoration: none;">%s</a>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="height: 15px;"></td>
                                </tr>
                                <tr>
                                    <td style="padding: 15px; background-color: #f9fafb; border-left: 4px solid #dc2626; margin-bottom: 15px;">
                                        <p style="margin: 0 0 8px 0; color: #6b7280; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">
                                            📞 Téléphone
                                        </p>
                                        <p style="margin: 0; color: #1a1a1a; font-size: 16px; font-weight: 600;">
                                            %s
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="height: 15px;"></td>
                                </tr>
                                <tr>
                                    <td style="padding: 15px; background-color: #f9fafb; border-left: 4px solid #dc2626; margin-bottom: 15px;">
                                        <p style="margin: 0 0 8px 0; color: #6b7280; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">
                                            🌍 Langue
                                        </p>
                                        <p style="margin: 0; color: #1a1a1a; font-size: 16px; font-weight: 600;">
                                            %s
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="height: 15px;"></td>
                                </tr>
                                <tr>
                                    <td style="padding: 20px; background-color: #fef2f2; border-left: 4px solid #dc2626; border-radius: 4px;">
                                        <p style="margin: 0 0 12px 0; color: #6b7280; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">
                                            💬 Message
                                        </p>
                                        <p style="margin: 0; color: #1a1a1a; font-size: 15px; line-height: 1.6; white-space: pre-wrap;">%s</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td style="background-color: #1a1a1a; padding: 20px; text-align: center;">
                            <p style="margin: 0; color: #ffffff; font-size: 14px;">
                                <strong style="color: #dc2626;">Eldocam</strong> - Système de contact
                            </p>
                            <p style="margin: 5px 0 0 0; color: #999; font-size: 12px;">
                                Reçu le %s
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
    `, escapedName, escapedEmail, escapedEmail, escapedTel, form.Language, escapedMessage, time.Now().Format("02/01/2006 à 15:04"))

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
		TextPart: adminTextBody,
		HTMLPart: adminHTMLBody,
	}

	// Email de confirmation pour l'utilisateur
	var confirmSubject, confirmTextBody, confirmHTMLBody string

	switch strings.ToLower(form.Language) {
	case "en":
		confirmSubject = "Thank you for contacting Eldocam"
		confirmTextBody = fmt.Sprintf(`
Hello %s,

Thank you for contacting us. We have received your message and will get back to you as soon as possible.

Best regards,
The Eldocam Team
`, escapedName)
		confirmHTMLBody = fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;">
                                ✅ Message Received
                            </h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 15px 0; color: #1a1a1a; font-size: 18px;">
                                Hello <strong style="color: #dc2626;">%s</strong>,
                            </p>
                            <p style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Thank you for contacting us. We have received your message and will get back to you as soon as possible.
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
		confirmSubject = "Bedankt voor uw contact met Eldocam"
		confirmTextBody = fmt.Sprintf(`
Hallo %s,

Bedankt voor uw contact. We hebben uw bericht ontvangen en zullen zo spoedig mogelijk contact met u opnemen.

Met vriendelijke groet,
Het Eldocam Team
`, escapedName)
		confirmHTMLBody = fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;">
                                ✅ Bericht Ontvangen
                            </h1>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            <p style="margin: 0 0 15px 0; color: #1a1a1a; font-size: 18px;">
                                Hallo <strong style="color: #dc2626;">%s</strong>,
                            </p>
                            <p style="margin: 0 0 20px 0; color: #1a1a1a; font-size: 16px; line-height: 1.6;">
                                Bedankt voor uw contact. We hebben uw bericht ontvangen en zullen zo spoedig mogelijk contact met u opnemen.
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
                                Dit is een automatisch bericht, gelieve niet te antwoorden.
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

	default: // Français par défaut
		confirmSubject = "Merci de votre contact - Eldocam"
		confirmTextBody = fmt.Sprintf(`
Bonjour %s,

Merci de nous avoir contactés. Nous avons bien reçu votre message et nous vous répondrons dans les plus brefs délais.

Cordialement,
L'équipe Eldocam
`, escapedName)
		confirmHTMLBody = fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f5f5f5;">
    <table role="presentation" style="width: 100%%; border-collapse: collapse;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #dc2626 0%%, #991b1b 100%%); padding: 30px; text-align: center;">
                            <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;">
                                ✅ Message Reçu
                            </h1>
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

	// ✅ Routes corrigées
	http.HandleFunc("/health", healthHandler)
	http.Handle("/api/contact", corsHandler.Handler(http.HandlerFunc(contactHandler)))
	http.HandleFunc("/", rootHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	log.Printf("🚀 Serveur démarré sur le port %s", port)
	log.Printf("📍 Routes actives:")
	log.Printf("   GET  /health")
	log.Printf("   POST /api/contact")
	log.Printf("   GET  /")
	log.Printf("🔒 Rate limiting: 3 requêtes max par IP / 10 minutes")
	log.Printf("🛡️ Cloudflare Turnstile: Activé")
	log.Printf("🚫 Détection de spam: Activée")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("❌ Erreur serveur:", err)
	}
}
