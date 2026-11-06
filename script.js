/* ========================================
   ASBILY CONTROLLER
   Main JavaScript
======================================== */

"use strict";

// ========================================
// Mobile Navigation
// ========================================

const menuToggle = document.getElementById("menuToggle");
const navigation = document.getElementById("navigation");

if (menuToggle && navigation) {

  menuToggle.addEventListener("click", () => {

    const isOpen = navigation.classList.toggle("active");

    menuToggle.setAttribute(
      "aria-expanded",
      String(isOpen)
    );

  });

  // Close menu after clicking a navigation link

  navigation.querySelectorAll("a").forEach((link) => {

    link.addEventListener("click", () => {

      navigation.classList.remove("active");

      menuToggle.setAttribute(
        "aria-expanded",
        "false"
      );

    });

  });

  // Close menu when Escape is pressed

  document.addEventListener("keydown", (event) => {

    if (event.key === "Escape") {

      navigation.classList.remove("active");

      menuToggle.setAttribute(
        "aria-expanded",
        "false"
      );

    }

  });

}

// ========================================
// Dynamic Copyright Year
// ========================================

const currentYear = document.getElementById("currentYear");

if (currentYear) {
  currentYear.textContent = new Date().getFullYear();
}

// ========================================
// Controller Frontend Status
// ========================================

console.info(
  "Asbily Controller frontend initialized."
);
