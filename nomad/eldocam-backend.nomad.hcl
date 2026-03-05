variable "image_tag" {
  type    = string
  default = "latest"
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

      config {
        image = "ghcr.io/sebbemercier/eldocam-backend:${var.image_tag}"
        ports = ["http"]
      }

      # Workload Identity : Nomad injecte un JWT de courte durée dans /secrets/vault_jwt
      # Ce JWT est utilisé par l'app pour s'authentifier à Vault sans token fixe
      identity {
        name = "vault_jwt"
        aud  = ["vault.io"]
        file = true
        ttl  = "1h"
      }

      env {
        VAULT_ADDR = "http://master-nomad.groupmercier.tmg:8200"
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
