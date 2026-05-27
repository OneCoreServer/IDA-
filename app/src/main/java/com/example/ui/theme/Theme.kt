package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Premium Professional Polish Palette (aligned with IDA Pro dark style)
private val ColorDarkBg = Color(0xFF0D1117)
private val ColorPanelBg = Color(0xFF161B22)
private val ColorAccentPrimary = Color(0xFF58A6FF)
private val ColorAccentSecondary = Color(0xFF1F6FEB)
private val ColorExportGreen = Color(0xFF4EC9B0)
private val ColorTextLight = Color(0xFFC9D1D9)
private val ColorBorder = Color(0xFF30363D)

private val DarkColorScheme =
  darkColorScheme(
    primary = ColorAccentPrimary,
    secondary = ColorAccentSecondary,
    tertiary = ColorExportGreen,
    background = ColorDarkBg,
    surface = ColorPanelBg,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = ColorTextLight,
    onSurface = ColorTextLight,
    outline = ColorBorder
  )

private val LightColorScheme =
  lightColorScheme(
    primary = ColorAccentPrimary,
    secondary = ColorAccentSecondary,
    tertiary = ColorExportGreen,
    background = ColorDarkBg,
    surface = ColorPanelBg,
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = ColorTextLight,
    onSurface = ColorTextLight,
    outline = ColorBorder
  )

@Composable
fun MyApplicationTheme(
  darkTheme: Boolean = true, // Force elite decompiler dark theme always
  dynamicColor: Boolean = false, // Disable dynamic colors to keep professional IDA styles
  content: @Composable () -> Unit,
) {
  val colorScheme = DarkColorScheme // Always use premium decompiler developer dark theme

  MaterialTheme(colorScheme = colorScheme, typography = Typography, content = content)
}
