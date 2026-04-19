variable "image_tag" {
  type    = string
  default = "latest"
}

variable "vault_token" {
  type    = string
  default = ""
}

job "eldocam-backend" {
  region      = "global"
  datacenters = ["dc1"]
  type        = "service"
  
  meta {
    version     = "1.0.0"
    project     = "eldocam"
    environment = "production"
  }

  group "api" {
    count = 2

    vault {
      policies = ["eldocam-backend"]
    }

    update {
      max_parallel     = 1
      min_healthy_time = "10s"
      healthy_deadline = "3m"
      auto_revert      = true
      canary           = 0
    }

    network {
      port "http" {
        to = 8000
      }
    }

    service {
      name = "eldocam-backend"
      port = "http"
      
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.eldocam-api.rule=Host(`api.eldocam.com`)",
        "traefik.http.routers.eldocam-api.entrypoints=websecure",
        "traefik.http.routers.eldocam-api.tls.certresolver=cloudflare",
        "traefik.http.routers.eldocam-api.tls=true",
      ]

      check {
        type     = "http"
        path     = "/health"
        interval = "10s"
        timeout  = "2s"
      }
    }

    task "server" {
      driver = "docker"

      template {
        destination = "local/eldocam.env"
        env         = true
        change_mode = "restart"
        data = <<-EOH
{{ with secret "secret/data/eldocam" -}}
MAILJET_API_KEY={{ .Data.data.mailjet_api_key }}
MAILJET_SECRET_KEY={{ .Data.data.mailjet_secret_key }}
SENDER_EMAIL={{ .Data.data.sender_email }}
SENDER_NAME={{ .Data.data.sender_name }}
ADMIN_TO={{ .Data.data.admin_to }}
TURNSTILE_SECRET={{ .Data.data.turnstile_secret }}
{{- end }}
EOH
      }

      config {
        image = "ghcr.io/sebbemercier/eldocam-backend:${var.image_tag}"
        ports = ["http"]
      }

      env {
        VAULT_ADDR  = "http://master-nomad.groupmercier.tmg:8200"
      }

      resources {
        cpu    = 200
        memory = 256
      }

      logs {
        max_files     = 5
        max_file_size = 10
      }
    }
  }
}
