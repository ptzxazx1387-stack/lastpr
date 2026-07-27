#pragma once
#include "sdk/classes.h"
#include "sdk/math.h"
#include "imgui/imgui.h"
#include <vector>

namespace ESP {
    void DrawLine(Vector3 start, Vector3 end, ImU32 color, Matrix viewMatrix, int width, int height) {
        Vector2 s, e;
        if (WorldToScreen(start, s, viewMatrix, width, height) &&
            WorldToScreen(end, e, viewMatrix, width, height)) {
            ImGui::GetOverlayDrawList()->AddLine(ImVec2(s.x, s.y), ImVec2(e.x, e.y), color, 1.2f);
        }
    }

    void DrawBox(Vector3 position, float height, ImU32 color, Matrix viewMatrix, int screenWidth, int screenHeight) {
        Vector2 top, bottom;
        Vector3 topWorld = { position.x, position.y + height, position.z };
        
        if (WorldToScreen(position, bottom, viewMatrix, screenWidth, screenHeight) &&
            WorldToScreen(topWorld, top, viewMatrix, screenWidth, screenHeight)) {
            
            float h = bottom.y - top.y;
            float w = h / 2.0f;

            ImGui::GetOverlayDrawList()->AddRect(
                ImVec2(top.x - (w / 2), top.y),
                ImVec2(top.x + (w / 2), bottom.y),
                color,
                0.0f, 0, 1.2f
            );
        }
    }

    void Render(const std::vector<PlayerData>& players, Matrix viewMatrix, int width, int height, float fps) {
        char watermark[64];
        sprintf_s(watermark, "by .presidental - FPS: %.0f", fps);
        ImGui::GetOverlayDrawList()->AddText(ImVec2(10, 10), IM_COL32(255, 255, 255, 255), watermark);

        for (const auto& player : players) {
            if (!player.isValid || player.position.empty()) continue;

            ImU32 col = player.isSleeping ? IM_COL32(150, 150, 150, 255) : IM_COL32(255, 255, 255, 255);// 1 sleepers color, 2 active players color

            DrawBox(player.position, 1.8f, col, viewMatrix, width, height);

            Vector2 screenPos;
            if (WorldToScreen(player.position, screenPos, viewMatrix, width, height)) {
                std::string label = player.name;
                if (player.isSleeping) label += " [sleeping]";

                ImGui::GetOverlayDrawList()->AddText(
                    ImVec2(screenPos.x, screenPos.y - 15.0f),
                    col,
                    label.c_str()
                );
            }
        }
    }
}
