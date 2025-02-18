#pragma once
#include "imgui.h"

#define IMRGBA(r, g, b, a) ImVec4(r / 255.f, g / 255.f, b / 255.f, a / 255.f)
#define THEME_COL_UNUSED ImVec4(0.f, 0.f, 0.f, 0.f)
#define THEME_COL_WARNING ImGuiCol_COUNT
#define THEME_COL_ERROR (ImGuiCol_COUNT + 1)

ImVec4 Dark[ImGuiCol_COUNT + 2] = {
    IMRGBA(255, 255, 255, 255),
    IMRGBA(127, 127, 127, 255),
    IMRGBA(25, 25, 25, 255),
    THEME_COL_UNUSED,
    IMRGBA(20, 20, 20, 240),
    IMRGBA(110, 110, 127, 127),
    THEME_COL_UNUSED,
    IMRGBA(40, 40, 40, 255),
    IMRGBA(60, 60, 60, 255),
    IMRGBA(75, 75, 75, 255),
    IMRGBA(25, 25, 25, 255),
    IMRGBA(25, 25, 25, 255),
    IMRGBA(0, 0, 0, 130),
    IMRGBA(35, 35, 35, 255),
    IMRGBA(5, 5, 5, 135),
    IMRGBA(75, 75, 75, 255),
    IMRGBA(100, 100, 100, 255),
    IMRGBA(130, 130, 130, 255),
    IMRGBA(100, 100, 100, 255),
    IMRGBA(75, 75, 75, 255),
    IMRGBA(100, 100, 100, 255),
    IMRGBA(40, 40, 40, 255),
    IMRGBA(60, 60, 60, 255),
    IMRGBA(80, 80, 80, 255),
    IMRGBA(40, 40, 40, 255),
    IMRGBA(60, 60, 60, 255),
    IMRGBA(80, 80, 80, 255),
    IMRGBA(40, 40, 40, 255),
    IMRGBA(60, 60, 60, 255),
    IMRGBA(80, 80, 80, 255),
    IMRGBA(40, 40, 40, 255),
    IMRGBA(60, 60, 60, 255),
    IMRGBA(80, 80, 80, 255),
    IMRGBA(60, 60, 60, 255),
    IMRGBA(40, 40, 40, 255),
    IMRGBA(80, 80, 80, 255),
    THEME_COL_UNUSED,
    IMRGBA(20, 25, 35, 255),
    IMRGBA(35, 60, 105, 255),
    THEME_COL_UNUSED,
    IMRGBA(150, 150, 150, 255),
    IMRGBA(255, 110, 90, 255),
    IMRGBA(230, 180, 0, 255),
    IMRGBA(255, 150, 0, 255),
    IMRGBA(45, 45, 50, 255),
    IMRGBA(75, 75, 90, 255),
    IMRGBA(60, 60, 60, 255),
    THEME_COL_UNUSED,
    IMRGBA(255, 255, 255, 15),
    IMRGBA(255, 255, 255, 255),
    IMRGBA(255, 0, 0, 255),
    IMRGBA(255, 255, 0, 229),
    IMRGBA(255, 0, 0, 255),
    IMRGBA(255, 255, 255, 178),
    IMRGBA(204, 204, 204, 50),
    IMRGBA(204, 204, 204, 90),

    // SPECIAL COLORS
    IMRGBA(255, 255, 255, 255),
    IMRGBA(255, 255, 255, 255)
};

ImVec4 Light[ImGuiCol_COUNT + 2] = {

    // SPECIAL COLORS
};

ImVec4* Themes[] = {
    Dark,
    Dark
};