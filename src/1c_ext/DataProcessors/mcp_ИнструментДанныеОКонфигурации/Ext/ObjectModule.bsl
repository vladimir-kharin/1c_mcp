﻿#Область Переменные

Перем ЯзыкСинтаксиса;

#КонецОбласти

#Область ПрограммныйИнтерфейс

Функция ОписаниеСтруктурыОбъектаМетаданных(МетаданныеОбъекта) Экспорт

	ЯзыкСинтаксиса = ?(
		Метаданные.ВариантВстроенногоЯзыка = Метаданные.СвойстваОбъектов.ВариантВстроенногоЯзыка.Английский,
		"en",
		"ru");
	
	МассивСтрок = Новый Массив;
	
	// Заголовок объекта
	МетаТип = СтрРазделить(МетаданныеОбъекта.ПолноеИмя(), ".")[0];
	ВывестиЗаголовокОбъектаМетаданных(МассивСтрок, МетаданныеОбъекта, МетаТип);
	
	СтруктураСтандартныеРеквизиты = Новый Структура("СтандартныеРеквизиты");
	ЗаполнитьЗначенияСвойств(СтруктураСтандартныеРеквизиты, МетаданныеОбъекта);
	Если СтруктураСтандартныеРеквизиты.СтандартныеРеквизиты <> Неопределено Тогда
		ВывестиСписокРеквизитовМетаданных(МассивСтрок, МетаданныеОбъекта.СтандартныеРеквизиты, НСтр("ru='Стандартные реквизиты';en='Standard attributes'"));
	КонецЕсли;

	// Обработка измерений и ресурсов для регистров
	ЭтоРегистр = ЭтоРегистрМД(МетаданныеОбъекта);
	Если ЭтоРегистр Тогда
		ВывестиСписокРеквизитовМетаданных(МассивСтрок, МетаданныеОбъекта.Измерения, НСтр("ru='Измерения';en='Dimensions'"));
		ВывестиСписокРеквизитовМетаданных(МассивСтрок, МетаданныеОбъекта.Ресурсы, НСтр("ru='Ресурсы';en='Resources'"));
	КонецЕсли;
	
	ВывестиСписокРеквизитовМетаданных(МассивСтрок, МетаданныеОбъекта.Реквизиты, НСтр("ru='Реквизиты';en='Attributes'"));

	Если Метаданные.Справочники.Содержит(МетаданныеОбъекта) И МетаданныеОбъекта.Владельцы.Количество() > 0 Тогда
		ВывестиВладельцевМетаданных(МассивСтрок, МетаданныеОбъекта);
	КонецЕсли;
	
	Если Не ЭтоРегистр Тогда
		ВывестиТабличныеЧастиМетаданных(МассивСтрок, МетаданныеОбъекта.ТабличныеЧасти);
	КонецЕсли;
	
	// Объединяем строки через символ перевода строки
	Результат = СтрСоединить(МассивСтрок, Символы.ПС);
	
	Возврат Результат;

КонецФункции

#КонецОбласти

#Область СлужебныеПроцедурыИФункции

#Область ИнструментСтруктураОбъекта

Функция ЭтоРегистрМД(МетаданныеОбъекта)

	Возврат Метаданные.РегистрыБухгалтерии.Содержит(МетаданныеОбъекта)
		ИЛИ Метаданные.РегистрыНакопления.Содержит(МетаданныеОбъекта)
		ИЛИ Метаданные.РегистрыРасчета.Содержит(МетаданныеОбъекта)
		ИЛИ Метаданные.РегистрыСведений.Содержит(МетаданныеОбъекта);

КонецФункции

Функция ПолучитьСтрокуТипаМетаданных(ТипРеквизита)

	МассивСтрокТипов = Новый Массив;
	
	Для Каждого Тип Из ТипРеквизита.Типы() Цикл
		ТипМД = Метаданные.НайтиПоТипу(Тип);
		
		Если ТипМД = Неопределено Тогда
			МассивСтрокТипов.Добавить(Строка(Тип));
		Иначе
			СтрокаТипа = ТипМД.ПолноеИмя();
			
			Если Метаданные.Перечисления.Содержит(ТипМД) Тогда
				МассивЗначений = Новый Массив;
				Счетчик = 0;
				Для Каждого ЗначениеПеречисления Из ТипМД.ЗначенияПеречисления Цикл
					Если Счетчик < 10 Тогда
						МассивЗначений.Добавить(ЗначениеПеречисления.Имя);
						Счетчик = Счетчик + 1;
					Иначе
						МассивЗначений.Добавить("...");
						Прервать;
					КонецЕсли;
				КонецЦикла;
				
				Если МассивЗначений.Количество() > 0 Тогда
					СтрокаЗначений = СтрСоединить(МассивЗначений, ", ");
					СтрокаТипа = СтрокаТипа + " (" + СтрокаЗначений + ")";
				КонецЕсли;
			КонецЕсли;
			МассивСтрокТипов.Добавить(СтрокаТипа);
		КонецЕсли;
	КонецЦикла;
	
	Возврат СтрСоединить(МассивСтрокТипов, ", ");

КонецФункции

Процедура ВывестиЗаголовокОбъектаМетаданных(МассивСтрок, МетаданныеОбъекта, МетаТип)

	МассивСтрок.Добавить(НСтр("ru='Структура объекта ';en='Object structure '") + МетаТип + "." + МетаданныеОбъекта.Имя + ":");
	МассивСтрок.Добавить(НСтр("ru='Синоним: ';en='Synonym: '") + """" + МетаданныеОбъекта.Синоним + """");
	МассивСтрок.Добавить("");

КонецПроцедуры

Процедура ВывестиСписокРеквизитовМетаданных(МассивСтрок, Реквизиты, ИмяРаздела)

	Если Реквизиты.Количество() > 0 Тогда
		МассивСтрок.Добавить(ИмяРаздела + ":");
		
		Для каждого Реквизит Из Реквизиты Цикл
			ТипРекв_Стр = ПолучитьСтрокуТипаМетаданных(Реквизит.Тип);
			МассивСтрок.Добавить(Символы.Таб + Реквизит.Имя + " - " + ТипРекв_Стр + " - """ + Реквизит.Синоним + """");
		КонецЦикла;
		
		МассивСтрок.Добавить("");
	КонецЕсли;

КонецПроцедуры

Процедура ВывестиТабличныеЧастиМетаданных(МассивСтрок, ТабличныеЧасти)

	Если ТабличныеЧасти.Количество() > 0 Тогда
		МассивСтрок.Добавить(НСтр("ru='Табличные части:';en='Tabular sections:'"));
		
		Для каждого ТабЧасть Из ТабличныеЧасти Цикл
			МассивСтрок.Добавить(Символы.Таб + НСтр("ru='ТЧ ';en='TS '") + """" + ТабЧасть.Имя + """ - """ + ТабЧасть.Синоним + """:");
			
			Для каждого Реквизит Из ТабЧасть.Реквизиты Цикл
				ТипРекв_Стр = ПолучитьСтрокуТипаМетаданных(Реквизит.Тип);
				МассивСтрок.Добавить(Символы.Таб + Символы.Таб + Реквизит.Имя + " - " + ТипРекв_Стр + " - """ + Реквизит.Синоним + """");
			КонецЦикла;
		КонецЦикла;
		
		МассивСтрок.Добавить("");
	КонецЕсли;

КонецПроцедуры

Процедура ВывестиВладельцевМетаданных(МассивСтрок, МетаданныеОбъекта)

	МассивСтрок.Добавить(НСтр("ru='Владельцы:';en='Owners:'"));
	
	Для каждого Владелец Из МетаданныеОбъекта.Владельцы Цикл
		МассивСтрок.Добавить(Символы.Таб + Владелец.ПолноеИмя());
	КонецЦикла;
	
	МассивСтрок.Добавить("");

КонецПроцедуры

#КонецОбласти

#КонецОбласти
